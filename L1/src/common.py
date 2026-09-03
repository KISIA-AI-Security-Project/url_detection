"""common.py — 인프라 조회 세 부품·실패 처리·기록·출구·검증이 함께 쓰는 기록 구조체와 어휘."""

from dataclasses import dataclass

__all__ = [
    "InfraRecord",
    "INFRA_STATUS_RECEIVED",
    "INFRA_STATUS_TIMEOUT",
    "INFRA_STATUS_NOT_QUERIED",
    "INFRA_STATUS_TOOL_ERROR",
    "NAME_DNS_A",
    "NAME_DNS_AAAA",
    "NAME_DNS_NS",
    "NAME_IP_ASN",
    "NAME_RDAP",
    "REASON_HOST_IS_IP",
    "DNS_TIMEOUT_S",
    "DNS_LIFETIME_S",
    "OVERALL_COMPLETED",
    "OVERALL_FAILED",
    "FAILURE_PROBE_SILENT",
    "FAILURE_BUDGET_EXCEEDED",
]

# 인프라 조회 status 어휘 넷. 앞머리 INFRA_는 평판 조회 어휘(L1 밖 reputation 모듈, 같은 낱말 Timeout·Not Queried 포함)와 갈라 두기 위함.
INFRA_STATUS_RECEIVED: str = "응답 수신"
INFRA_STATUS_TIMEOUT: str = "Timeout"
INFRA_STATUS_NOT_QUERIED: str = "Not Queried"
INFRA_STATUS_TOOL_ERROR: str = "도구 오류"

# 관측 이름 다섯. 부품 셋·4번 실패 처리·5번 기록·출구가 문자열을 직접 쓰지 않고 이 이름을 쓴다.
NAME_DNS_A: str = "DNS A"
NAME_DNS_AAAA: str = "DNS AAAA"
NAME_DNS_NS: str = "DNS NS"
NAME_IP_ASN: str = "IP·ASN"
NAME_RDAP: str = "RDAP"

# dns.py와 rdap.py가 같은 문장을 쓰는데 부품끼리는 import하지 않으므로 common.py에 둔다.
REASON_HOST_IS_IP: str = "호스트가 IP 주소라 물을 이름이 없음"

# DIG 기본 절차(시도당 5초 × 3회)를 dnspython 값으로 옮긴 것. dns.py·ip_asn.py·failure.py가 같이 읽는다 —
# 한쪽만 바뀌면 조회와 대조의 절차가 어긋나 「같은 길이 막혔나」를 못 잰다.
DNS_TIMEOUT_S: float = 5.0
DNS_LIFETIME_S: float = 15.0

# 출구의 전체상태 둘과 실패사유 둘. handler가 정하고 records가 적고 검증이 읽는 세 곳의 어휘라 여기 둔다.
# 실패사유는 파일에 「실패」가 적히는 두 경우만 — 코드 오류·저장 실패는 파일 자체가 안 만들어져 여기 없다.
OVERALL_COMPLETED: str = "완료"
OVERALL_FAILED: str = "실패"
FAILURE_PROBE_SILENT: str = "관측 무효(대조 무응답)"
FAILURE_BUDGET_EXCEEDED: str = "관측 무효(예산 초과)"


@dataclass(frozen=True)
class InfraRecord:
    name: str
    status: str
    result: dict | str | None = None   # 없음 = None. 저장 때 None 칸을 빼는 일은 5번 기록·출구가 한다
    detail: dict | None = None
    reason: str | None = None
