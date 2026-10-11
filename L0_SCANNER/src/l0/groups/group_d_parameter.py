"""Each query value that resolves to an external URL host, without navigation."""
import re
from ada_url import URL
from l0.common import GROUP_D_EXTERNAL_QUERY
from l0.models import CheckResult, observation, analysis_error
from l0.parsing import ParseResult, _tldextract

_URL_PREFIX = re.compile(r"^(?:[a-zA-Z][a-zA-Z0-9+.-]*:|[/\\]{2})")

def check_external_query_address(result: ParseResult) -> CheckResult:
    if not result.parsed or not result.query:
        return CheckResult()
    source_host = result.parsed.hostname.lower().rstrip(".")
    source_domain = result.extracted.registered_domain.lower().rstrip(".") if result.extracted else ""
    source_is_ip = result.parsed.host_type in {"IPV4", "IPV6"}
    records, errors = [], []
    for key, values in result.query.items():
        for index, value in enumerate(values):
            if not _URL_PREFIX.match(value.strip()):
                continue
            target_location = {"parameter": key, "value_index": index, "value": value}
            try:
                target = URL(value, base=result.parsed.href)
            except (ValueError, TypeError) as exc:
                errors.append(analysis_error(GROUP_D_EXTERNAL_QUERY, "query_target_parse_failed",
                                             target=target_location, error=exc))
                continue
            target_host = target.hostname.lower().rstrip(".")
            if not target_host or target_host == source_host:
                continue
            target_is_ip = target.host_type.name in {"IPV4", "IPV6"}
            target_domain = "" if target_is_ip else _tldextract(target_host).top_domain_under_public_suffix.lower().rstrip(".")
            if (not source_is_ip and not source_domain) or (not target_is_ip and not target_domain):
                errors.append(analysis_error(GROUP_D_EXTERNAL_QUERY, "query_target_domain_unresolved", target=target_location))
                continue
            if source_domain and target_domain == source_domain:
                continue
            records.append(observation(GROUP_D_EXTERNAL_QUERY, {
                "URL의_등록_도메인": source_domain or None, "URL_호스트": result.parsed.hostname,
                "쿼리_항목": key, "값_순번": index, "쿼리_값": value,
                "값에_들어_있는_호스트": target.hostname,
                "값에_들어_있는_등록_도메인": target_domain or None,
            }))
    return CheckResult(records, errors)

GROUP_D_DETECTORS = (check_external_query_address,)
