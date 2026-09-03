"""L3-J-07 Dynamic Redirect: 정책에 등록된 JavaScript 이동 API 관측."""

from typing import Any, Mapping

from ._common import result


def analyze(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Redirect 호출 수와 대표 API·목적지를 Evidence로 반환한다.

    목적지 페이지로 실제 이동하거나 콘텐츠를 수집하지 않는다. API 집합이 설정되지
    않은 경우 호출 부재를 음성으로 확정하지 않는다.
    """
    events = list(raw.get("redirects", []))
    representative = events[0] if events else {}
    evidence = {
        "redirect_count": len(events),
        "api": representative.get("api"),
        "destination_url": representative.get("destination_url"),
    }
    return result(
        raw,
        "L3-J-07",
        "dynamic_redirect",
        detected=bool(events),
        evidence=evidence,
        policy_resolved=bool(raw.get("analysis", {}).get("redirect_policy_configured")),
    )
