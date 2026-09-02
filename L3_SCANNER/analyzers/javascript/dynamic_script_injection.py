"""L3-J-03 Dynamic Script Injection: 생성된 script 요소의 DOM 삽입 관측."""

from typing import Any, Mapping

from ._common import result, unique


def analyze(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Script Injection 이벤트 수와 해석 가능한 URL·도메인을 요약한다.

    URL을 알 수 없어도 생성한 script 요소가 삽입된 구조 자체는 관측으로 유지한다.
    외부 Script를 실제 다운로드하거나 실행하지 않는다.
    """
    events = list(raw.get("script_injection", []))
    evidence = {
        "script_count": len(events),
        "urls": unique([event.get("url") for event in events if event.get("url")]),
        "domains": unique(
            [event.get("domain") for event in events if event.get("domain")]
        ),
    }
    return result(
        raw,
        "L3-J-03",
        "dynamic_script_injection",
        detected=bool(events),
        evidence=evidence,
    )
