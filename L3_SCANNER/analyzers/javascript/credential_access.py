"""L3-J-05 Credential Access: JavaScript의 인증 필드 값 접근 관측."""

from typing import Any, Mapping

from ._common import result, unique


def analyze(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Credential Source 이벤트를 유형·필드 식별자·횟수로 요약한다.

    값 자체는 Raw에도 Signal에도 존재하지 않는다. Credential 분류 정책이 없으면 DOM
    접근을 인증정보 접근으로 단정할 수 없으므로 판정은 미확정이다.
    """
    events = list(raw.get("credential_access", []))
    evidence = {
        "credential_types": unique(
            [
                event.get("credential_type")
                for event in events
                if event.get("credential_type")
            ]
        ),
        "fields": unique(
            [event.get("field_id") for event in events if event.get("field_id")]
        ),
        "access_count": len(events),
    }
    return result(
        raw,
        "L3-J-05",
        "credential_access",
        detected=bool(events),
        evidence=evidence,
        policy_resolved=bool(
            raw.get("analysis", {}).get("credential_policy_configured")
        ),
    )
