"""Username presence and PSL suffix labels embedded in subdomains."""
from l0.common import GROUP_E_HOST_SPOOFING, GROUP_E_SUBDOMAIN_ANOMALY
from l0.models import CheckResult, observation
from l0.parsing import ParseResult, _tldextract

_PSL_SUFFIXES = frozenset(_tldextract.tlds)

def check_host_spoofing(result: ParseResult) -> CheckResult:
    if not result.parsed or not result.parsed.username:
        return CheckResult()
    return CheckResult([observation(GROUP_E_HOST_SPOOFING, {
        "username": result.parsed.username, "실제_접속_호스트": result.parsed.hostname,
    })])

def check_subdomain_anomaly(result: ParseResult) -> CheckResult:
    if not result.extracted or not result.extracted.subdomain or not result.parsed:
        return CheckResult()
    labels = result.extracted.subdomain.lower().split(".")
    records = []
    for index, label in enumerate(labels):
        if label not in _PSL_SUFFIXES:
            continue
        start = max(0, index - 1)
        records.append(observation(GROUP_E_SUBDOMAIN_ANOMALY, {
            "호스트": result.parsed.hostname, "실제_등록_도메인": result.extracted.registered_domain,
            "서브도메인에서_발견한_부분": {
                "문자열": ".".join(labels[start:index + 1]), "일치한_suffix": label,
                "suffix_순번": index,
            },
        }))
    return CheckResult(records)

GROUP_E_DETECTORS = (check_host_spoofing, check_subdomain_anomaly)
