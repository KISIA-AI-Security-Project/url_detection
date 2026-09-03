"""L3-J-01 Dynamic Code Execution: 정책 API의 정적 호출 관측."""

from typing import Any, Mapping

from ._common import result, unique


def analyze(raw: Mapping[str, Any]) -> dict[str, Any]:
    """동적 실행 이벤트의 API·횟수·관측 출처를 Evidence로 요약한다.

    Parser가 만든 실제 Call/New AST 이벤트만 사용하며 단순 문자열 참조를 실행으로
    승격하지 않는다. API 정책이 없으면 판정은 미확정이다.
    """
    events = list(raw.get("dynamic_execution", []))
    evidence = {
        "apis": unique([event.get("api") for event in events if event.get("api")]),
        "execution_count": len(events),
        "origins": unique(
            [event.get("origin") for event in events if event.get("origin")]
        ),
    }
    return result(
        raw,
        "L3-J-01",
        "dynamic_code_execution",
        detected=bool(events),
        evidence=evidence,
        policy_resolved=bool(
            raw.get("analysis", {}).get("dynamic_execution_policy_configured")
        ),
    )
