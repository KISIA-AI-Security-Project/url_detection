"""L3-J-06 Credential Exfiltration: Credential Source→외부 Network Sink 관계."""

from typing import Any, Mapping

from ._common import result


def analyze(raw: Mapping[str, Any]) -> dict[str, Any]:
    """동일 데이터 흐름으로 연결된 인증 Source와 외부 Network Sink를 판정한다.

    인증 필드 접근과 외부 요청이 각각 존재한다는 이유만으로 관계를 만들지 않는다.
    ``source_links``가 증명하는 연결만 사용하고, 변환 계보와 양쪽 event id를 보존한다.
    """
    requests = list(raw.get("network_requests", []))
    linked = [
        (request, link)
        for request in requests
        if request.get("external") is True
        for link in request.get("source_links", [])
    ]
    if linked:
        request, link = linked[0]
        evidence = {
            "source": link.get("credential_type"),
            "field_id": link.get("field_id"),
            "transformations": list(link.get("transformations", [])),
            "sink": request.get("api"),
            "destination": request.get("destination_url"),
            "destination_etld1": request.get("destination_etld1"),
            "external": request.get("external"),
            "source_event_id": link.get("source_event_id"),
            "sink_event_id": request.get("event_id"),
        }
    else:
        evidence = {
            "source": None,
            "transformations": [],
            "sink": None,
            "destination": None,
            "destination_etld1": None,
            "external": None,
        }
    policy_resolved = bool(
        raw.get("analysis", {}).get("credential_policy_configured")
    ) and bool(raw.get("analysis", {}).get("network_policy_configured"))
    output = result(
        raw,
        "L3-J-06",
        "credential_exfiltration",
        detected=bool(linked),
        evidence=evidence,
        policy_resolved=policy_resolved,
    )
    # 별개의 Source와 Sink 관측만으로 유출을 주장할 수도, 연결 부재를 확정할 수도
    # 없다. 목적지까지 미확정인 연결 역시 음성이 아니라 unresolved로 보존한다.
    if (
        not linked
        and output["status"] == "evaluated"
        and output["detected"] is False
        and (
            (
                raw.get("credential_access")
                and any(item.get("external") is True for item in requests)
            )
            or any(
                item.get("source_links") and item.get("external") is None
                for item in requests
            )
        )
    ):
        output["detected"] = None
        output["error"] = {"code": "source_sink_or_destination_unresolved"}
    return output
