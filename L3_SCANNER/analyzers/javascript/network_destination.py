"""L3-J-04 Network Destination: JavaScript Network API 목적지 관측."""

from typing import Any, Mapping

from ._common import result, unique


def analyze(raw: Mapping[str, Any]) -> dict[str, Any]:
    """해석 가능한 Network 목적지를 API·eTLD+1·외부 여부로 구조화한다.

    Network 호출은 있으나 목적지를 정적으로 해석할 수 없으면 '목적지 없음'이 아니므로
    음성 판정을 ``None``으로 되돌린다. 실제 네트워크 요청은 보내지 않는다.
    """
    all_events = list(raw.get("network_requests", []))
    events = [event for event in all_events if event.get("destination_url")]
    evidence = {
        "request_count": len(events),
        "apis": unique([event.get("api") for event in events if event.get("api")]),
        "destinations": [
            {
                "url": event.get("destination_url"),
                "etld1": event.get("destination_etld1"),
                "external": event.get("external"),
            }
            for event in events
        ],
    }
    output = result(
        raw,
        "L3-J-04",
        "network_destination",
        detected=bool(events),
        evidence=evidence,
        policy_resolved=bool(raw.get("analysis", {}).get("network_policy_configured")),
    )
    if (
        not events
        and all_events
        and output["status"] == "evaluated"
        and output["detected"] is False
    ):
        output["detected"] = None
        output["error"] = {"code": "network_destination_unresolved"}
    return output
