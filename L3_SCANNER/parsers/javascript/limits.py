"""공유 JavaScript 관측 이벤트 전체에 단일 상한을 적용하는 모듈."""

from typing import Any

_EVENT_COLLECTIONS = (
    "dynamic_execution",
    "decode_operations",
    "script_injection",
    "network_requests",
    "dom_access",
    "credential_access",
    "redirects",
    "environment_access",
    "branches",
    "execution_trace",
)


def enforce_event_limit(raw: dict[str, Any], limit: int) -> None:
    """모든 이벤트 컬렉션을 합산 순서대로 제한하고 불완전 상태를 기록한다.

    개별 목록마다 상한을 적용하면 전체 메모리가 목록 수만큼 증가하므로 공통 예산을
    사용한다. 잘린 뒤에는 관측 부재를 확정할 수 없도록 ``source_complete=False``로
    표시한다.
    """
    remaining = max(limit, 0)
    truncated = False
    for key in _EVENT_COLLECTIONS:
        events = raw[key]
        if len(events) > remaining:
            del events[remaining:]
            truncated = True
        remaining -= len(events)
    if truncated and not any(
        error.get("code") == "javascript_event_limit_exceeded"
        for error in raw["errors"]
    ):
        raw["analysis"]["source_complete"] = False
        raw["errors"].append(
            {
                "code": "javascript_event_limit_exceeded",
                "message": "Static observation output exceeded the configured event limit.",
                "limit": limit,
            }
        )
