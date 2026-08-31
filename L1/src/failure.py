"""failure.py — Timeout 기록 하나를 받아 그 Timeout이 대상 탓인지 우리 쪽 네트워크 탓인지를 대조 조회로 가른다."""

from dataclasses import dataclass, field

import dns.resolver
import httpx

from src.common import (
    DNS_LIFETIME_S,
    DNS_TIMEOUT_S,
    INFRA_STATUS_TIMEOUT,
    NAME_DNS_A,
    NAME_DNS_AAAA,
    NAME_DNS_NS,
    NAME_IP_ASN,
    NAME_RDAP,
    InfraRecord,
)

__all__ = [
    "probe",
    "judge_timeout",
    "Probes",
    "PROBE_DNS",
    "PROBE_HTTP",
    "PROBE_BY_NAME",
    "TIME_BUDGET_S",
    "DNS_PROBE_NAME",
    "HTTP_PROBE_URL",
    "VERDICT_NOT_TIMEOUT",
    "VERDICT_TARGET_FAULT",
    "VERDICT_OUR_FAULT",
]

# 실행 시간 예산. 시계를 돌리는 것은 handler — 이 부품은 숫자만 준다.
TIME_BUDGET_S: float = 60.0
DNS_PROBE_NAME: str = "example.com"
# 명세는 스킴을 안 적었다. RDAP이 전부 https라 「같은 길」로 https.
HTTP_PROBE_URL: str = "https://www.google.com/generate_204"

PROBE_DNS: str = "dns"
PROBE_HTTP: str = "http"

# Timeout이 난 기록의 name → 붙이는 대조. IP·ASN도 DNS(TXT) 질의라 DNS 대조.
PROBE_BY_NAME: dict[str, str] = {
    NAME_DNS_A: PROBE_DNS,
    NAME_DNS_AAAA: PROBE_DNS,
    NAME_DNS_NS: PROBE_DNS,
    NAME_IP_ASN: PROBE_DNS,
    NAME_RDAP: PROBE_HTTP,
}

# 판별 결과 셋. 기록에 들어가지 않고 handler만 읽는 이 부품의 어휘라 common.py에 두지 않는다.
VERDICT_NOT_TIMEOUT: str = "Timeout 아님"
VERDICT_TARGET_FAULT: str = "대상 탓, 계속"
VERDICT_OUR_FAULT: str = "우리 탓, 실행 실패"


@dataclass
class Probes:
    """한 번 실행의 대조 장치. handler가 실행 시작 때 하나 만들어 judge_timeout마다 넘긴다.

    모듈 변수에 두지 않는 이유: Lambda 재사용 컨테이너에서는 실행이 끝나도 남아 다음 실행이 지난 대조 답을 물려받는다.
    """

    resolver: dns.resolver.Resolver | None = None   # None = 모듈 수준 _RESOLVER(시스템 리졸버). 검증은 침묵하는 주소의 리졸버를 넣는다
    http_url: str = HTTP_PROBE_URL                    # 검증은 침묵하는 주소의 URL을 넣는다
    answered: dict[str, bool] = field(default_factory=dict)   # 대조 종류 → 응답 여부. 이 실행에서 실제로 물은 종류만 들어 있다


def judge_timeout(record: InfraRecord, probes: Probes) -> str:
    """기록 하나 → 판별 결과 셋 중 하나. 같은 종류의 대조는 이 실행에서 한 번만 묻고 답을 다시 쓴다."""
    if record.status != INFRA_STATUS_TIMEOUT:
        return VERDICT_NOT_TIMEOUT
    kind = PROBE_BY_NAME[record.name]   # 표에 없는 name은 프로그래밍 오류라 KeyError가 그대로 나간다
    if kind not in probes.answered:
        probes.answered[kind] = probe(kind, probes)
    return VERDICT_TARGET_FAULT if probes.answered[kind] else VERDICT_OUR_FAULT


def probe(kind: str, probes: Probes) -> bool:
    """대조 하나를 실제로 묻는다. True = 상대가 보낸 답이 있음, False = 무응답(Timeout이든 그 밖의 예외든 — 길이 막힌 것)."""
    if kind == PROBE_DNS:
        return _probe_dns(probes.resolver or _RESOLVER)
    if kind == PROBE_HTTP:
        return _probe_http(probes.http_url)
    raise ValueError(f"모르는 대조 종류: {kind!r}")


def _probe_dns(resolver: dns.resolver.Resolver) -> bool:
    try:
        resolver.resolve(DNS_PROBE_NAME, "A")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.NoAnswer, dns.resolver.YXDOMAIN):
        return True   # 부정 응답도 리졸버가 답한 것 — 길은 뚫려 있다
    except Exception:
        return False
    return True


def _probe_http(url: str) -> bool:
    try:
        _CLIENT.get(url)   # 상태 코드는 보지 않는다. 5xx도 서버가 답한 것이고, generate_204는 몸이 비어 읽을 것도 없다
    except Exception:
        return False
    return True


# 조회(dns.py·ip_asn.py)와 같은 설정의 별도 객체 — 대조가 같은 절차로 같은 길을 재야 한다. 부품끼리 import하지 않아 여기 한 번 더 만든다.
_RESOLVER: dns.resolver.Resolver = dns.resolver.Resolver()
_RESOLVER.timeout = DNS_TIMEOUT_S
_RESOLVER.lifetime = DNS_LIFETIME_S

# httpx 기본 timeout 그대로(rdap.py와 같은 판정). RDAP용 redirect·Accept 설정은 대조에 필요 없어 붙이지 않는다.
_CLIENT: httpx.Client = httpx.Client()
