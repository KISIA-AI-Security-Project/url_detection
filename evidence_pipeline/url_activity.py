"""Narrow, scan-time DNS activity assessment from the producer's actual replies.

This is a reachability observation, not a URL safety verdict or an SSRF gate.
An unavailable HTTP response is never evidence that a name does not exist.
"""

from urllib.parse import urlsplit
from datetime import datetime, timedelta, timezone

import dns.message
import dns.flags
import dns.name
import dns.rcode
import dns.rdatatype
import dns.rdataclass


def _name(value):
    try:
        return dns.name.from_text(value, origin=dns.name.root).canonicalize()
    except Exception:
        return None


def _reply(raws, hostname, record_type):
    entry = raws.get(f"DNS {record_type}")
    if not isinstance(entry, dict) or len(entry) != 1:
        return None
    key, wire_text = next(iter(entry.items()))
    if not isinstance(key, str) or not isinstance(wire_text, str):
        return None
    queried, separator, kind = key.rpartition(" ")
    if not separator or kind != record_type or _name(queried) != _name(hostname):
        return None
    try:
        reply = dns.message.from_text(wire_text)
    except Exception:
        return None
    if not reply.flags & dns.flags.QR:
        return None
    if len(reply.question) != 1 or _name(reply.question[0].name.to_text()) != _name(hostname):
        return None
    if reply.question[0].rdtype != dns.rdatatype.from_text(record_type):
        return None
    if reply.question[0].rdclass != dns.rdataclass.IN:
        return None
    return reply


def _terminal_name(reply, hostname):
    """Follow only an unambiguous CNAME chain rooted at the exact query name."""
    aliases = {}
    for rrset in reply.answer:
        if rrset.rdclass != dns.rdataclass.IN:
            return None
        if rrset.rdtype == dns.rdatatype.CNAME:
            if len(rrset) != 1:
                return None
            owner = _name(rrset.name.to_text())
            target = _name(rrset[0].target.to_text())
            if owner is None or target is None:
                return None
            if owner in aliases and aliases[owner] != target:
                return None
            aliases[owner] = target
    current = _name(hostname)
    if current is None:
        return None
    seen = set()
    while current in aliases:
        if current in seen:
            return None
        seen.add(current)
        current = aliases[current]
    if set(aliases) != seen:
        return None
    return current


def _supported_nxdomain(reply, hostname):
    if reply.rcode() != dns.rcode.NXDOMAIN:
        return None
    # A positive answer in an NXDOMAIN packet is contradictory, regardless of
    # the native producer's summarized result. DNAME/other answer shapes are
    # not interpreted by this narrow classifier either.
    if any(rrset.rdtype != dns.rdatatype.CNAME for rrset in reply.answer):
        return None
    terminal = _terminal_name(reply, hostname)
    if terminal is None:
        return None
    soa_sets = [rrset for rrset in reply.authority if rrset.rdtype == dns.rdatatype.SOA]
    if len(soa_sets) != 1 or len(soa_sets[0]) != 1:
        return None
    soa = soa_sets[0]
    if soa.rdclass != dns.rdataclass.IN:
        return None
    soa_owner = _name(soa.name.to_text())
    if soa_owner is None or not terminal.is_subdomain(soa_owner):
        return None
    ttl = min(soa.ttl, soa[0].minimum)
    if ttl <= 0:
        return None
    return {"terminal_name": terminal.to_text(), "soa_owner": soa_owner.to_text(),
            "negative_ttl_s": ttl}


def _supported_nodata(reply, hostname):
    """Verify an exact A NODATA answer and its finite negative cache lifetime."""
    if reply.rcode()!=dns.rcode.NOERROR or not _no_address_answer(reply,hostname):
        return None
    if any(rrset.rdtype!=dns.rdatatype.CNAME for rrset in reply.answer):
        return None
    terminal=_terminal_name(reply,hostname)
    soa_sets=[rrset for rrset in reply.authority if rrset.rdtype==dns.rdatatype.SOA]
    if terminal is None or len(soa_sets)!=1 or len(soa_sets[0])!=1:
        return None
    soa=soa_sets[0]
    owner=_name(soa.name.to_text()) if soa.rdclass==dns.rdataclass.IN else None
    if owner is None or not terminal.is_subdomain(owner):
        return None
    ttl=min(soa.ttl,soa[0].minimum)
    if ttl<=0:return None
    return {'terminal_name':terminal.to_text(),'negative_ttl_s':ttl}


def _nxdomain_without_soa(reply, hostname):
    """Accept only the packet shape; an exact-name NS reply supplies TTL separately."""
    if reply.rcode() != dns.rcode.NXDOMAIN or reply.authority:
        return None
    if any(rrset.rdtype != dns.rdatatype.CNAME for rrset in reply.answer):
        return None
    terminal = _terminal_name(reply, hostname)
    return terminal.to_text() if terminal is not None else None


def _verified_addresses(reply, hostname, record_type, claimed):
    if reply.rcode() != dns.rcode.NOERROR or not claimed:
        return False
    terminal = _terminal_name(reply, hostname)
    if terminal is None:
        return False
    actual = [rdata.to_text() for rrset in reply.answer
              if _name(rrset.name.to_text()) == terminal and
              rrset.rdclass == dns.rdataclass.IN and
              rrset.rdtype == dns.rdatatype.from_text(record_type)
              for rdata in rrset]
    return bool(actual) and set(actual) == set(claimed)


def _no_address_answer(reply, hostname):
    if reply.rcode() != dns.rcode.NOERROR or _terminal_name(reply, hostname) is None:
        return False
    return not any(rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA)
                   for rrset in reply.answer)


def l1_address_resolution_failed(url, native, raws):
    """The A lookup explicitly failed; missing or contradictory data is not failure."""
    try:
        hostname = urlsplit(url).hostname
    except ValueError:
        return False
    if not hostname or native.get("전체상태") != "완료" or (native.get("도메인단위") or {}).get("호스트 종류") != "도메인":
        return False
    items = {item.get("name"): item for item in native.get("인프라결과_목록", [])
             if isinstance(item, dict)}
    for kind in ("A",):
        item = items.get(f"DNS {kind}")
        if not isinstance(item, dict):
            return False
        if item.get("status") == "Timeout" and item.get("result") is None:
            if raws.get(f"DNS {kind}"):
                return False
            continue
        result = item.get("result")
        if item.get("status") != "응답 수신":
            return False
        if isinstance(result, dict) and result.get("records") == []:
            reply = _reply(raws, hostname, kind)
            if reply is None or not _no_address_answer(reply, hostname):
                return False
            continue
        if isinstance(result, str):
            expected_codes = {result}
        elif isinstance(result, dict) and isinstance(result.get("response_codes"), list):
            expected_codes = set(result["response_codes"])
        else:
            return False
        if not expected_codes or not expected_codes <= {"NXDOMAIN", "SERVFAIL", "REFUSED"}:
            return False
        entry = raws.get(f"DNS {kind}")
        if not isinstance(entry, dict) or len(entry) != 1:
            return False
        key, wire = next(iter(entry.items()))
        if not isinstance(wire, str) or not wire:
            return False
        replies = [_reply({f"DNS {kind}": {key: part}}, hostname, kind)
                   for part in wire.split("\n\n")]
        if any(reply is None or any(rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA)
                                    for rrset in reply.answer) for reply in replies):
            return False
        if {dns.rcode.to_text(reply.rcode()) for reply in replies} != expected_codes:
            return False
    return True


def _positive_l23(records):
    for record in records:
        coverage = record.get("coverage") or {}
        if record.get("layer") == "l2" and (coverage.get("http_response_received") is True or
                                               coverage.get("tls_certificate_observed") is True):
            return True
        if record.get("layer") == "l3" and coverage.get("html_parsed") is True:
            return True
    return False


def _negative_expiry(item, ttl):
    value = (item.get("detail") or {}).get("observed_at")
    if not isinstance(value, str):
        return None
    try:
        observed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if observed.tzinfo is None:
        return None
    observed = observed.astimezone(timezone.utc)
    if observed > datetime.now(timezone.utc):
        return None
    return observed + timedelta(seconds=ttl)


def assess_url_activity(url, l1_native, l1_raw, records, *, request_id=None, attempt=None):
    """Return a conservative observation for this run's exact URL hostname.

    The caller must not reuse it as a current result after the scan; negative
    DNS answers have only the recorded TTL and require a new query later.
    """
    try:
        hostname = urlsplit(url).hostname
    except ValueError:
        hostname = None
    basis = {"scope": "scan_time_dns_observation", "hostname": hostname,
             "l23_positive_observation": _positive_l23(records),
             "identity_binding": "unverified", "can_skip_judgment": False}
    if request_id is not None or attempt is not None:
        matched = (request_id is not None and attempt is not None and
                   l1_native.get("job_id") == request_id and
                   str(l1_native.get("attempt_id")) == str(attempt))
        relevant = [r for r in records if r.get("layer") in ("l1", "l2", "l3")]
        matched = matched and {r.get("layer") for r in relevant} == {"l1", "l2", "l3"}
        matched = matched and all(
            r.get("request_id") == request_id and str(r.get("attempt")) == str(attempt) and
            (r.get("target") or {}).get("original_url") == url and
            (r.get("provenance") or {}).get("mode") == "current" for r in relevant)
        if not matched:
            return {"state": "DNS_UNKNOWN", "reason": "same_run_identity_unverified", **basis}
        basis["identity_binding"] = "verified"
    def unresolved(reason):
        if basis["l23_positive_observation"]:
            return {"state": "URL_REACHABLE_OBSERVED", "reason": "l23_http_tls_or_document_observed", **basis}
        return {"state": "DNS_UNKNOWN", "reason": reason, **basis}
    if not hostname:
        return unresolved("hostname_missing")
    if l1_native.get("전체상태") != "완료":
        return unresolved("l1_observation_not_validated")
    units = l1_native.get("도메인단위") or {}
    if units.get("호스트 종류") in ("IPv4", "IPv6"):
        return {"state": "DNS_NOT_APPLICABLE", "reason": "ip_literal", **basis}
    if units.get("호스트 종류") != "도메인":
        return unresolved("host_kind_unrecorded")
    items = {item.get("name"): item for item in l1_native.get("인프라결과_목록", [])
             if isinstance(item, dict)}
    item=items.get('DNS A')
    if item is None:
        return unresolved("address_query_missing")
    result=item.get('result')
    reply=_reply(l1_raw,hostname,'A')
    if (item.get('status')=='응답 수신' and isinstance(result,dict) and
            isinstance(result.get('records'),list) and result['records'] and
            reply is not None and _verified_addresses(reply,hostname,'A',result['records'])):
        return {'state':'DNS_ACTIVE','reason':'positive_a_address',**basis}
    negative=None
    if item.get('status')=='응답 수신' and reply is not None:
        if result=='NXDOMAIN':
            negative=_supported_nxdomain(reply,hostname)
            state,reason='DNS_NAME_NONEXISTENT_AT_SCAN','a_nxdomain_with_soa'
            if negative is None:
                bare=_nxdomain_without_soa(reply,hostname)
                ns_item=items.get('DNS NS')
                ns_reply=_reply(l1_raw,hostname,'NS')
                ns=_supported_nxdomain(ns_reply,hostname) if ns_reply is not None else None
                if (bare and isinstance(ns_item,dict) and ns_item.get('status')=='응답 수신'
                        and ns_item.get('result')=='NXDOMAIN' and ns and ns['terminal_name']==bare):
                    negative=ns
                    reason='a_nxdomain_with_ns_soa'
        elif isinstance(result,dict) and result.get('records')==[]:
            negative=_supported_nodata(reply,hostname)
            state,reason='URL_UNREACHABLE_AT_SCAN','a_nodata_with_soa'
    if negative:
        expiries=[_negative_expiry(item,negative['negative_ttl_s'])]
        if reason=='a_nxdomain_with_ns_soa':
            expiries.append(_negative_expiry(ns_item,negative['negative_ttl_s']))
        expiry=min(expiries) if all(expiries) else None
        if expiry is None or expiry<=datetime.now(timezone.utc):
            return unresolved('negative_dns_observation_expired_or_undated')
        if basis['l23_positive_observation']:
            return {'state':'DNS_CONFLICT','reason':'a_negative_and_l23_positive',**basis}
        return {'state':state,'reason':reason,'terminal_name':negative['terminal_name'],
                'negative_ttl_s':negative['negative_ttl_s'],'valid_until':expiry.isoformat(),
                **basis,'can_skip_judgment':basis['identity_binding']=='verified'}
    if basis["l23_positive_observation"]:
        return {"state": "URL_REACHABLE_OBSERVED", "reason": "l23_http_tls_or_document_observed", **basis}
    return {"state": "DNS_UNKNOWN", "reason": "address_evidence_incomplete_or_error", **basis}
