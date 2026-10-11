"""The DNS/HTTP boundary must not turn missing observations into a dead URL."""

import dns.message
import dns.rcode
import dns.rdataclass
import dns.rrset
from datetime import datetime, timezone

from evidence_pipeline.url_activity import assess_url_activity, l1_address_resolution_failed


HOST = "example.test"
URL = "https://example.test/login"


def reply(kind, *, code="NXDOMAIN", soa=True, address=None, cname=None, question=HOST):
    response = dns.message.make_response(dns.message.make_query(question, kind))
    response.set_rcode(dns.rcode.from_text(code))
    if cname:
        response.answer.append(dns.rrset.from_text(question, 300, "IN", "CNAME", cname))
    if address:
        owner = cname or question
        response.answer.append(dns.rrset.from_text(owner, 300, "IN", kind, address))
    if soa:
        response.authority.append(dns.rrset.from_text("test.", 300, "IN", "SOA",
            "ns.test. hostmaster.test. 1 3600 600 86400 120"))
    return response.to_text()


def inputs(a="NXDOMAIN", *, a_raw=None):
    values = {"A": a}
    native = {"도메인단위": {"호스트 종류": "도메인"}, "인프라결과_목록": [], "전체상태": "완료"}
    raws = {}
    for kind in ("A",):
        value = values[kind]
        item = {"name": f"DNS {kind}", "status": "Timeout" if value == "TIMEOUT" else "응답 수신",
                "result": None if value == "TIMEOUT" else {"records": ["192.0.2.10"]} if value == "POSITIVE" else
                {"records": []} if value == "NODATA" else value,
                "detail": {"observed_at": datetime.now(timezone.utc).isoformat()}}
        native["인프라결과_목록"].append(item)
        if value != "TIMEOUT":
            raw = a_raw
            if raw is None:
                raw = reply(kind, code="NOERROR" if value in ("POSITIVE", "NODATA") else value,
                            address="192.0.2.10" if value == "POSITIVE" else None)
            raws[f"DNS {kind}"] = {f"{HOST} {kind}": raw}
    return native, raws


def assess(native, raws, records=()):
    return assess_url_activity(URL, native, raws, records)


def test_a_supported_nxdomain_only_establishes_scan_time_name_absence():
    native, raws = inputs()
    result = assess(native, raws)
    assert result["state"] == "DNS_NAME_NONEXISTENT_AT_SCAN"
    assert result["negative_ttl_s"] == 120
    assert result["terminal_name"] == "example.test."


def test_timeout_servfail_and_l23_acquisition_failure_are_unknown():
    native, raws = inputs("TIMEOUT")
    records = [{"layer": "l2", "coverage": {"http_response_received": False,
                "tls_certificate_observed": False}}, {"layer": "l3", "coverage": {"html_parsed": False}}]
    assert assess(native, raws, records)["state"] == "DNS_UNKNOWN"
    assert l1_address_resolution_failed(URL, native, raws) is True
    native["인프라결과_목록"][0]["result"] = "NXDOMAIN"
    assert l1_address_resolution_failed(URL, native, raws) is False


def test_no_address_and_mixed_resolver_errors_are_explicit_resolution_failures():
    native, raws = inputs("NODATA")
    assert l1_address_resolution_failed(URL, native, raws) is True
    native, raws = inputs("SERVFAIL")
    assert l1_address_resolution_failed(URL, native, raws) is True
    native["인프라결과_목록"][0]["result"] = {"response_codes": ["SERVFAIL", "REFUSED"]}
    raws["DNS A"] = {f"{HOST} A": reply("A", code="SERVFAIL") + "\n\n" +
                     reply("A", code="REFUSED")}
    assert l1_address_resolution_failed(URL, native, raws) is True
    native["인프라결과_목록"][0]["status"] = "도구 오류"
    assert l1_address_resolution_failed(URL, native, raws) is False


def test_address_and_http_observation_are_distinct_positive_paths():
    native, raws = inputs("POSITIVE")
    assert assess(native, raws)["state"] == "DNS_ACTIVE"
    native, raws = inputs("TIMEOUT")
    records = [{"layer": "l2", "coverage": {"http_response_received": True}}]
    assert assess(native, raws, records)["state"] == "URL_REACHABLE_OBSERVED"
    assert assess_url_activity(URL, {}, {}, records)["state"] == "URL_REACHABLE_OBSERVED"


def test_l23_positive_conflicts_with_supported_nxdomain():
    native, raws = inputs()
    records = [{"layer": "l2", "coverage": {"tls_certificate_observed": True}}]
    assert assess(native, raws, records)["state"] == "DNS_CONFLICT"


def test_no_soa_or_wrong_question_cannot_confirm_absence():
    native, raws = inputs(a_raw=reply("A", soa=False))
    assert assess(native, raws)["state"] == "DNS_UNKNOWN"
    native, raws = inputs(a_raw=reply("A", question="other.test"))
    assert assess(native, raws)["state"] == "DNS_UNKNOWN"


def test_same_run_ns_soa_can_anchor_exact_a_nxdomain_without_authority():
    native, raws = inputs(a_raw=reply("A", soa=False))
    ns_item = {"name": "DNS NS", "status": "응답 수신", "result": "NXDOMAIN",
               "detail": {"observed_at": datetime.now(timezone.utc).isoformat()}}
    native["인프라결과_목록"].append(ns_item)
    raws["DNS NS"] = {f"{HOST} NS": reply("NS")}
    result = assess(native, raws)
    assert result["state"] == "DNS_NAME_NONEXISTENT_AT_SCAN"
    assert result["reason"] == "a_nxdomain_with_ns_soa"
    assert result["negative_ttl_s"] == 120

    raws["DNS NS"] = {f"{HOST} NS": reply("NS", question="other.test")}
    assert assess(native, raws)["state"] == "DNS_UNKNOWN"
    raws["DNS NS"] = {f"{HOST} NS": reply("NS")}
    native["인프라결과_목록"][-1]["detail"]["observed_at"] = "2000-01-01T00:00:00+00:00"
    assert assess(native, raws)["state"] == "DNS_UNKNOWN"


def test_ns_corroboration_rejects_other_dns_outcomes_and_wrong_soa():
    native, raws = inputs(a_raw=reply("A", soa=False))
    native["인프라결과_목록"].append({
        "name": "DNS NS", "status": "응답 수신", "result": "NXDOMAIN",
        "detail": {"observed_at": datetime.now(timezone.utc).isoformat()}})
    raws["DNS NS"] = {f"{HOST} NS": reply("NS", code="NOERROR")}
    assert assess(native, raws)["state"] == "DNS_UNKNOWN"
    wrong_soa = dns.message.from_text(reply("NS"))
    wrong_soa.authority.clear()
    wrong_soa.authority.append(dns.rrset.from_text("other.", 300, "IN", "SOA",
        "ns.other. hostmaster.other. 1 3600 600 86400 120"))
    raws["DNS NS"] = {f"{HOST} NS": wrong_soa.to_text()}
    assert assess(native, raws)["state"] == "DNS_UNKNOWN"
    raws["DNS NS"] = {f"{HOST} NS": reply("NS")}
    native["인프라결과_목록"][0]["result"] = "SERVFAIL"
    assert assess(native, raws)["state"] == "DNS_UNKNOWN"


def test_contradictory_positive_answer_or_wrong_query_class_cannot_skip():
    contradictory = dns.message.from_text(reply("A"))
    contradictory.answer.append(dns.rrset.from_text(HOST, 300, "IN", "A", "192.0.2.10"))
    native, raws = inputs(a_raw=contradictory.to_text())
    assert assess(native, raws)["state"] == "DNS_UNKNOWN"

    wrong_class = dns.message.make_response(
        dns.message.make_query(HOST, "A", rdclass=dns.rdataclass.CH))
    wrong_class.set_rcode(dns.rcode.NXDOMAIN)
    wrong_class.authority.append(dns.rrset.from_text("test.", 300, "IN", "SOA",
        "ns.test. hostmaster.test. 1 3600 600 86400 120"))
    native, raws = inputs(a_raw=wrong_class.to_text())
    assert assess(native, raws)["state"] == "DNS_UNKNOWN"


def test_wrong_authority_or_cname_class_cannot_confirm_name_absence():
    wrong_soa = dns.message.from_text(reply("A"))
    wrong_soa.authority.clear()
    wrong_soa.authority.append(dns.rrset.from_text("test.", 300, "CH", "SOA",
        "ns.test. hostmaster.test. 1 3600 600 86400 120"))
    native, raws = inputs(a_raw=wrong_soa.to_text())
    assert assess(native, raws)["state"] == "DNS_UNKNOWN"

    wrong_cname = dns.message.from_text(reply("A"))
    wrong_cname.answer.append(dns.rrset.from_text(HOST, 300, "CH", "CNAME", "alias.test."))
    native, raws = inputs(a_raw=wrong_cname.to_text())
    assert assess(native, raws)["state"] == "DNS_UNKNOWN"


def test_nodata_and_unverified_positive_result():
    native, raws = inputs("NODATA")
    assert assess(native, raws)["state"] == "URL_UNREACHABLE_AT_SCAN"
    native["job_id"]="job";native["attempt_id"]="1"
    records=[{'layer':layer,'request_id':'job','attempt':'1',
              'target':{'original_url':URL},'provenance':{'mode':'current'}}
             for layer in ('l1','l2','l3')]
    assert assess_url_activity(URL,native,raws,records,request_id='job',attempt='1')['can_skip_judgment'] is True
    native,raws=inputs('NODATA',a_raw=reply('A',code='NOERROR',soa=False))
    assert assess(native,raws)['state']=='DNS_UNKNOWN'
    native, raws = inputs("POSITIVE", a_raw=reply("A", code="NOERROR"))
    assert assess(native, raws)["state"] == "DNS_UNKNOWN"
    native, raws = inputs("NODATA",
                          a_raw=reply("A", code="NOERROR", address="192.0.2.10"))
    assert assess(native, raws)["state"] == "DNS_UNKNOWN"


def test_a_cname_negative_response_is_bound_to_terminal_name():
    native, raws = inputs(a_raw=reply("A", cname="one.test."))
    assert assess(native, raws)["state"] == "DNS_NAME_NONEXISTENT_AT_SCAN"


def test_expired_or_unbound_negative_cannot_skip_model():
    native, raws = inputs()
    native["인프라결과_목록"][0]["detail"]["observed_at"] = "2000-01-01T00:00:00+00:00"
    assert assess(native, raws)["state"] == "DNS_UNKNOWN"
    native, raws = inputs()
    assert assess(native, raws)["can_skip_judgment"] is False
    native["전체상태"] = "실패"
    assert assess(native, raws)["state"] == "DNS_UNKNOWN"
    native["전체상태"] = "완료"
    native["인프라결과_목록"][0]["detail"]["observed_at"] = "2099-01-01T00:00:00+00:00"
    assert assess(native, raws)["state"] == "DNS_UNKNOWN"


def test_same_run_identity_must_match_all_consumed_records():
    native, raws = inputs()
    native.update(job_id="job-1", attempt_id="1")
    records = [{"layer": layer, "request_id": "job-1", "attempt": "1",
                "target": {"original_url": URL}, "provenance": {"mode": "current"}}
               for layer in ("l1", "l2", "l3")]
    result = assess_url_activity(URL, native, raws, records, request_id="job-1", attempt="1")
    assert result["can_skip_judgment"] is True
    records[1]["target"]["original_url"] = "https://other.test/"
    result = assess_url_activity(URL, native, raws, records, request_id="job-1", attempt="1")
    assert result["state"] == "DNS_UNKNOWN"
    assert result["can_skip_judgment"] is False


def test_fast_pipeline_preserves_scan_time_absence_without_model_call(tmp_path):
    from evidence_pipeline.pipeline import FastPipeline

    class EmptyCollector:
        def scan_url(self, _url):
            return {"layers": {"l2": {}, "l3": {}}, "errors": []}

    native, raws = inputs()
    native.update(job_id="dns-absence", attempt_id="1")
    called = []
    result = FastPipeline(collector=EmptyCollector(), l1_runner=lambda _url: (native, raws),
                          judgment=lambda *_args: called.append(True)).run(
                              URL, output_root=tmp_path, request_id="dns-absence")
    assert result["url_activity"]["state"] == "DNS_NAME_NONEXISTENT_AT_SCAN"
    assert result["judgment_status"] == "not_requested_dns_name_nonexistent_at_scan"
    assert not called
    folder = tmp_path / "dns-absence" / "1"
    assert (folder / "result.json").is_file()
    assert (folder / "url-activity.json").is_file()
    assert not (folder / "context-for-model.json").exists()
    assert not (folder / "judgment-input.json").exists()


def test_preparation_failure_does_not_claim_a_model_input(tmp_path):
    from evidence_pipeline.pipeline import FastPipeline

    class EmptyCollector:
        def scan_url(self, _url):
            return {"layers": {"l2": {}, "l3": {}}, "errors": []}

    class FailedPreparation:
        def prepare_context(self, _system, _context):
            raise ValueError("preparation_failed")

        def __call__(self, *_args):
            raise AssertionError("model_must_not_be_called")

    result = FastPipeline(collector=EmptyCollector(), l1_runner=lambda _url: ({}, {}),
                          judgment=FailedPreparation()).run(
                              URL, output_root=tmp_path, request_id="preparation-failure")
    folder = tmp_path / "preparation-failure" / "1"
    assert result["judgment_status"] == "service_failed"
    assert not (folder / "context-for-model.json").exists()
    assert not (folder / "judgment-input.json").exists()
