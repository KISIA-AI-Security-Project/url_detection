"""Exact host-type and reference-list matches; no network access."""
import ipaddress
from l0.common import GROUP_A_IP_HOST, GROUP_A_SUSPICIOUS_TLD, GROUP_A_FREE_ISSUED_DOMAIN
from l0.models import CheckResult, observation
from l0.parsing import ParseResult
from l0.data.free_hosting import FREE_HOSTING_PROVIDERS
from l0.data.tld_lists import TLD_BLACK, TLD_BLACK_VERSION

def check_ip_host(result: ParseResult) -> CheckResult:
    parsed = result.parsed
    if parsed is None or parsed.host_type not in {"IPV4", "IPV6"}:
        return CheckResult()
    address = ipaddress.ip_address(parsed.hostname.strip("[]"))
    return CheckResult([observation(GROUP_A_IP_HOST, {
        "호스트": parsed.hostname, "IP_종류": f"IPv{address.version}",
    })])

def check_suspicious_tld(result: ParseResult) -> CheckResult:
    extracted = result.extracted
    if extracted is None or not extracted.suffix:
        return CheckResult()
    tld = extracted.suffix.lower().rsplit(".", 1)[-1]
    if tld not in TLD_BLACK:
        return CheckResult()
    return CheckResult([observation(GROUP_A_SUSPICIOUS_TLD, {
        "등록_도메인": extracted.registered_domain,
        "일치한_TLD": tld, "목록_버전": TLD_BLACK_VERSION,
    })])

def check_free_issued_domain(result: ParseResult) -> CheckResult:
    extracted = result.extracted
    if extracted is None or not extracted.subdomain or not result.parsed:
        return CheckResult()
    provider = extracted.registered_domain.lower().rstrip(".")
    category = FREE_HOSTING_PROVIDERS.get(provider)
    if category is None:
        return CheckResult()
    categories = {"HOSTING": "호스팅", "SERVERLESS": "서버리스", "DDNS": "동적 DNS", "TUNNEL": "터널링"}
    return CheckResult([observation(GROUP_A_FREE_ISSUED_DOMAIN, {
        "URL_호스트": result.parsed.hostname, "일치한_서비스_도메인": provider,
        "하위_주소": extracted.subdomain, "서비스_유형": categories[category],
    })])

GROUP_A_DETECTORS = (check_ip_host, check_suspicious_tld, check_free_issued_domain)
