"""L0 positive-only records: exact conditions, counterexamples, and storage."""
import json
from copy import deepcopy
from urllib.parse import quote
import pytest

from l0.registry import analyze, ALL_DETECTORS
from l0.common import JUDGMENT_HINTS, JUDGMENT_GUIDANCE
from evidence_pipeline.records import build_record, canonical, digest
from evidence_pipeline.record_contract import validate_record


def records(url, name=None):
    native = analyze(url)
    assert native["errors"] == []
    result = native["observations"]
    assert all(set(row) == {"검사", "관찰", "판단에 쓸 점"} for row in result)
    return [row for row in result if name is None or row["검사"] == name]


@pytest.mark.parametrize("url,name", [
    ("http://192.0.2.1/", "IP_호스트"),
    ("https://example.top/", "피싱_빈발_TLD_목록_일치"),
    ("https://sample.onrender.com/", "무료_발급_도메인"),
    ("https://unlistedbrand-login.example.net/", "호스트_단어_분리"),
    ("https://nаver.com/", "IDN_문자_변환"),
    ("https://example.net/invoice.pdf.exe", "이중_확장자"),
    ("https://bit.ly/sample", "단축_서비스_목록_일치"),
    ("https://example.net/?arbitrary=https%3A%2F%2Fexample.org%2F", "쿼리의_외부_주소"),
    ("https://example.org@example.net/", "접속_호스트_교란"),
    ("https://service.com.example.net/", "서브도메인_구조_이상"),
])
def test_each_retained_check_has_an_observed_positive(url, name):
    found = records(url, name)
    assert found
    assert all(row["판단에 쓸 점"] == JUDGMENT_HINTS[name] for row in found)


def test_success_with_no_matches_emits_no_records():
    native = analyze("https://www.example.com/")
    assert len(ALL_DETECTORS) == len(JUDGMENT_HINTS) == 10
    assert native["observations"] == []
    assert native["analysis_execution"]["record_count"] == 0
    assert native["judgment_guidance"] == JUDGMENT_GUIDANCE
    assert "evaluations" not in native and "analysis_records" not in native


@pytest.mark.parametrize("url,ip_kind", [
    ("http://0xC0000201/", "IPv4"), ("http://3221225985/", "IPv4"),
    ("http://[2001:db8::1]/", "IPv6"),
])
def test_ip_uses_parser_normalized_host(url, ip_kind):
    row = records(url, "IP_호스트")[0]["관찰"]
    assert row["IP_종류"] == ip_kind
    assert row["호스트"] == analyze(url)["raw_evidence"]["parsed"]["hostname"]


@pytest.mark.parametrize("provider", [
    "onrender.com", "wordpress.com", "blogspot.com", "azurewebsites.net", "appspot.com", "run.app",
    "github.io", "workers.dev",
])
def test_provider_match_requires_exact_domain_and_subdomain(provider):
    assert records("https://sample." + provider + "/", "무료_발급_도메인")
    assert records("https://" + provider + "/", "무료_발급_도메인") == []
    assert records("https://sample." + provider + ".example.net/", "무료_발급_도메인") == []


def test_repeated_host_labels_and_both_separators_are_not_collapsed():
    rows = records("https://alpha-beta.alpha-beta.gamma_delta.example.net/", "호스트_단어_분리")
    assert len(rows) == 3
    assert [r["관찰"]["부분_순번"] for r in rows] == [0, 1, 2]
    assert rows[2]["관찰"]["분리된_단어"] == ["gamma", "delta"]
    assert records("https://unknownbrandlogin.example.net/", "호스트_단어_분리") == []


def test_idn_has_no_brand_reference_gate_and_no_fake_punycode_separator():
    row = records("https://аbcdefgh.com/", "IDN_문자_변환")[0]["관찰"]
    assert row == {"실제_접속_호스트": "аbcdefgh.com", "비교용_표기": "abcdefgh.com"}
    assert records("https://аbcdefgh.com/", "호스트_단어_분리") == []
    assert records("https://example.com/", "IDN_문자_변환") == []
    assert records("https://中文.com/", "IDN_문자_변환") == []
    assert records("https://bücher-login.example.net/", "호스트_단어_분리")[0]["관찰"]["분리된_단어"] == ["bücher", "login"]


def test_double_extensions_keep_each_location_and_repeated_query_value():
    url = "https://example.net/report.pdf.exe?file=one.doc.lnk&file=two.png.js&file=normal.pdf"
    rows = records(url, "이중_확장자")
    assert len(rows) == 3
    assert rows[0]["관찰"]["위치"] == "URL 경로의 마지막 부분"
    assert [r["관찰"]["값_순번"] for r in rows[1:]] == [0, 1]
    for path in ("normal.pdf", "file.exe", "file.tar.gz", "file.pdf..exe", "file.pdf.exe/"):
        assert records("https://example.net/" + path, "이중_확장자") == []


def test_shortener_membership_is_not_a_suffix_substring_match():
    assert records("https://bit.ly.example.net/", "단축_서비스_목록_일치") == []
    assert records("https://notbit.ly/", "단축_서비스_목록_일치") == []
    assert records("https://bit.ly./sample", "단축_서비스_목록_일치")


def test_query_values_are_independent_and_keys_have_no_redirect_semantics_gate():
    url = ("https://example.net/?arbitrary=https%3A%2F%2Fexample.org%2Fa"
           "&arbitrary=https%3A%2F%2Fexample.org%2Fb&arbitrary=justtext"
           "&same=https%3A%2F%2Fsub.example.net%2F&relative=%2Flogin&proto=%2F%2Fexample.com%2Fx")
    rows = records(url, "쿼리의_외부_주소")
    assert len(rows) == 3
    assert [r["관찰"]["값_순번"] for r in rows[:2]] == [0, 1]
    assert rows[2]["관찰"]["값에_들어_있는_호스트"] == "example.com"
    assert records("https://example.net/", "쿼리의_외부_주소") == []


def test_ip_source_does_not_call_itself_external():
    assert records("http://192.0.2.1/?a=http%3A%2F%2F192.0.2.1%2Fx", "쿼리의_외부_주소") == []
    assert records("http://192.0.2.1/?a=http%3A%2F%2F192.0.2.2%2Fx", "쿼리의_외부_주소")


def test_username_comes_from_parser_not_at_sign_in_path():
    assert records("https://example.net/a@b?mail=user@example.org", "접속_호스트_교란") == []
    row = records("https://first@second@example.net/", "접속_호스트_교란")[0]["관찰"]
    assert row == {"username": "first%40second", "실제_접속_호스트": "example.net"}


def test_all_embedded_suffix_occurrences_survive():
    rows = records("https://first.com.second.org.example.net/", "서브도메인_구조_이상")
    assert [r["관찰"]["서브도메인에서_발견한_부분"]["문자열"] for r in rows] == ["first.com", "second.org"]
    assert records("https://aa1.bb2.cc3.dd4.example.net/", "서브도메인_구조_이상") == []


@pytest.mark.parametrize("url", ["", "not a URL", "http://[invalid"])
def test_parse_failure_preserves_raw_and_never_runs_checks(url):
    native = analyze(url)
    assert native["raw_evidence"]["raw_url"] == url
    assert native["observations"] == []
    assert native["analysis_execution"]["state"] == "not_run"


def test_malformed_query_does_not_hide_other_query_observation():
    native = analyze("https://example.net/?bad=%E7&file=doc.pdf.exe&a=https%3A%2F%2Fexample.org%2F")
    assert native["raw_evidence"]["query_status"] == "partial"
    assert {r["검사"] for r in native["observations"]} >= {"이중_확장자", "쿼리의_외부_주소"}
    saved = build_record("l0", native, request_id="offline", attempt=1)
    assert saved["analysis"]["state"] == "partial"
    assert saved["errors"]


def test_invalid_targets_are_errors_not_negative_or_positive_records():
    native = analyze("https://example.net/?a=http%3A%2F%2F%5Binvalid&a=http%3A%2F%2F%5Binvalid&a=https%3A%2F%2Fexample.org")
    assert len(native["errors"]) == 2
    assert len({e["occurrence_id"] for e in native["errors"]}) == 2
    assert len(native["observations"]) == 1
    assert native["observations"][0]["관찰"]["값_순번"] == 2


def test_check_exception_keeps_other_positives(monkeypatch):
    import l0.registry as registry
    def broken(_):
        raise RuntimeError("offline failure")
    monkeypatch.setattr(registry, "ALL_DETECTORS", (broken, *ALL_DETECTORS))
    native = registry.analyze("http://192.0.2.1/")
    assert len(native["errors"]) == 1
    assert native["observations"][0]["검사"] == "IP_호스트"


def test_missing_shortener_reference_is_a_separate_error(monkeypatch):
    from l0.groups import group_c_link_file as group
    monkeypatch.setattr(group, "SHORTENERS_VERSION", "unavailable")
    native = analyze("https://example.net/report.pdf.exe")
    assert native["errors"]
    assert any(r["검사"] == "이중_확장자" for r in native["observations"])
    assert not any(r["검사"] == "단축_서비스_목록_일치" for r in native["observations"])


def test_removed_checks_do_not_return_via_heuristic_inputs():
    url = "ftp://g00gle.com:1234/a.exe?x=" + quote("<script>alert(1)</script>") + "&b=aHR0cHM6Ly9ldmlsLmNvbS8=" + "&long=" + "x" * 10000
    native = analyze(url)
    assert native["observations"] == []
    assert native["judgment_guidance"] == JUDGMENT_GUIDANCE


def test_actual_raw_and_records_round_trip_without_a_builder(tmp_path):
    url = "https://user:pass@www.example.net:8443/a/../download/report.pdf.exe?file=guide.pdf&file=report.doc.exe&return=https%3A%2F%2Fother.example.org%2Flogin#section"
    native = analyze(url)
    original = deepcopy(native)
    record = build_record("l0", native, request_id="l0-review", attempt=1)
    for name, value in (("raw-l0.json", native["raw_evidence"]), ("record-l0.json", record), ("native-l0.json", native)):
        (tmp_path / name).write_bytes(canonical(value))
    raw = json.loads((tmp_path / "raw-l0.json").read_text(encoding="utf-8"))
    saved = json.loads((tmp_path / "record-l0.json").read_text(encoding="utf-8"))
    validate_record(saved)
    assert native == original
    assert raw == native["raw_evidence"]
    assert "query" not in raw
    assert "file=guide.pdf&file=report.doc.exe" in raw["parsed"]["search"]
    assert raw["parsed"]["pathname"] == "/download/report.pdf.exe"
    assert saved["raw_ref"]["sha256"] == digest(raw)
    assert saved["signals"] == native["observations"]


def test_query_keeps_question_mark_in_key_instead_of_merging_distinct_keys():
    from ada_url import parse_search_params
    from l0.parsing import parse_url_stage
    url = "https://example.net/??a=https%3A%2F%2Fexample.org%2F&a=https%3A%2F%2Fexample.com%2F"
    native = analyze(url)
    raw = native["raw_evidence"]
    assert "query" not in raw
    parsed_query = parse_url_stage(url).query
    assert parsed_query == parse_search_params(raw["parsed"]["search"])
    assert list(parsed_query) == ["?a", "a"]
    assert [row["관찰"]["쿼리_항목"] for row in native["observations"]] == ["?a", "a"]

