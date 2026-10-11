"""Configured double-extension pairs and shortener-list membership."""
from urllib.parse import unquote
from l0.common import GROUP_C_DOUBLE_EXTENSION, GROUP_C_SHORT_URL
from l0.models import CheckResult, observation
from l0.parsing import ParseResult
from l0.data.extensions import EXTENSION_RISK_MAP
from l0.data.shorteners import SHORTENER_DOMAINS, SHORTENERS_VERSION

def _candidates(result):
    if result.parsed:
        segment = unquote(result.parsed.pathname.rsplit("/", 1)[-1])
        if segment:
            yield segment, {"위치": "URL 경로의 마지막 부분"}
    for key, values in result.query.items():
        for index, value in enumerate(values):
            if value:
                yield value, {"위치": "쿼리 값", "쿼리_항목": key, "값_순번": index}

def check_double_extension(result: ParseResult) -> CheckResult:
    records = []
    for text, location in _candidates(result):
        tokens = text.rsplit(".", 2)
        if len(tokens) != 3 or not tokens[0]:
            continue
        first, last = tokens[-2].lower(), tokens[-1].lower()
        a, b = EXTENSION_RISK_MAP.get(first), EXTENSION_RISK_MAP.get(last)
        if a and b and a[1] == "DECEPTIVE" and b[1] == "DANGEROUS":
            records.append(observation(GROUP_C_DOUBLE_EXTENSION, {
                **location, "검사한_문자열": text, "앞_확장자": first, "마지막_확장자": last,
            }))
    return CheckResult(records)

def check_short_url(result: ParseResult) -> CheckResult:
    if not result.parsed or not result.extracted or not result.extracted.registered_domain:
        return CheckResult()
    if SHORTENERS_VERSION == "unavailable" or not SHORTENER_DOMAINS:
        raise RuntimeError("shortener list unavailable")
    hostname = result.parsed.hostname.lower().rstrip(".")
    registered = result.extracted.registered_domain.lower().rstrip(".")
    provider = hostname if hostname in SHORTENER_DOMAINS else registered
    if provider not in SHORTENER_DOMAINS:
        return CheckResult()
    return CheckResult([observation(GROUP_C_SHORT_URL, {
        "URL_호스트": result.parsed.hostname, "일치한_목록_항목": provider,
        "목록_버전": SHORTENERS_VERSION,
    })])

GROUP_C_DETECTORS = (check_double_extension, check_short_url)
