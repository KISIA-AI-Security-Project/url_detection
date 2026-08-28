"""L3-J-02 Obfuscation/Decode Chain: Decode에서 실행으로 이어진 계보 관측."""

from typing import Any, Mapping

from ._common import result, unique


def analyze(raw: Mapping[str, Any]) -> dict[str, Any]:
    """동일 데이터 계보로 연결된 Decode→Dynamic Execution만 탐지한다.

    Decode 호출만 존재하는 경우 방법은 Evidence에 남길 수 있지만 J-02 양성으로 보지
    않는다. Decode와 실행 API 정책이 모두 있어야 음성 결과도 확정할 수 있다.
    """
    decode_events = list(raw.get("decode_operations", []))
    linked = [
        event for event in raw.get("dynamic_execution", []) if event.get("decode_links")
    ]
    methods = unique(
        [
            link.get("method")
            for event in linked
            for link in event.get("decode_links", [])
            if link.get("method")
        ]
        or [event.get("method") for event in decode_events if event.get("method")]
    )
    chain = []
    if linked:
        first = linked[0]
        chain = [
            *[link["method"] for link in first.get("decode_links", [])],
            first.get("api"),
        ]
    evidence = {
        "methods": methods,
        "chain": [item for item in chain if item],
        "execution_connected": True if linked else False,
    }
    return result(
        raw,
        "L3-J-02",
        "obfuscation_decode_chain",
        detected=bool(linked),
        evidence=evidence,
        policy_resolved=(
            bool(raw.get("analysis", {}).get("decode_policy_configured"))
            and bool(raw.get("analysis", {}).get("dynamic_execution_policy_configured"))
        ),
    )
