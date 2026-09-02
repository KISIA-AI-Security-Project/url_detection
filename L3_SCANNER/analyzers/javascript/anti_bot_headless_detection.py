"""L3-J-08 Anti-Bot/Headless Detection: 브라우저 환경 속성 읽기 관측."""

from typing import Any, Mapping

from ._common import result, unique


def analyze(raw: Mapping[str, Any]) -> dict[str, Any]:
    """설정된 환경 속성의 읽기 목록과 횟수를 H-08 Evidence로 요약한다.

    속성을 읽었다는 관측만 제공하며 CAPTCHA 우회, 사용자 환경 변경, cloaking 판정은
    수행하지 않는다. 속성 정책이 없으면 음성 결과를 만들지 않는다.
    """
    events = list(raw.get("environment_access", []))
    evidence = {
        "properties": unique(
            [event.get("property") for event in events if event.get("property")]
        ),
        "check_count": len(events),
    }
    return result(
        raw,
        "L3-J-08",
        "anti_bot_headless_detection",
        detected=bool(events),
        evidence=evidence,
        policy_resolved=bool(raw.get("analysis", {}).get("anti_bot_policy_configured")),
    )
