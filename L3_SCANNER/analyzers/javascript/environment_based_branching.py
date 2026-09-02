"""L3-J-09 Environment-Based Branching: 환경값에 따른 상이한 동작 분기."""

from typing import Any, Mapping

from L3_SCANNER.policies.detection import DetectionPolicy

from ._common import result, unique


def analyze(
    raw: Mapping[str, Any], policy: DetectionPolicy | None = None
) -> dict[str, Any]:
    """환경 조건의 두 분기를 정책으로 정규화해 동작 차이가 있을 때만 탐지한다.

    환경 속성 읽기만으로 J-09를 만들지 않는다. 양쪽 branch가 모두 비교 가능한 동작으로
    정규화되고 서로 다를 때만 관계가 성립하며, L4 실행 여부는 결정하지 않는다.
    """
    normalizer = getattr(policy, "branch_behavior_normalizer", None) if policy else None
    qualifying: list[tuple[Mapping[str, Any], list[str | None]]] = []
    for event in raw.get("branches", []):
        branches = list(event.get("branches", []))
        normalized = [normalizer(branch) for branch in branches] if normalizer else []
        if (
            len(normalized) >= 2
            and normalized[0] is not None
            and normalized[1] is not None
        ):
            if normalized[0] != normalized[1]:
                qualifying.append((event, normalized))

    evidence = {
        "properties": unique(
            [prop for event, _ in qualifying for prop in event.get("properties", [])]
        ),
        "conditions": unique(
            [
                event.get("condition")
                for event, _ in qualifying
                if event.get("condition")
            ]
        ),
        "branch_behaviors": [
            {
                "condition_result": branch.get("condition_result"),
                "behavior": normalized[index],
            }
            for event, normalized in qualifying
            for index, branch in enumerate(event.get("branches", []))
        ],
    }
    return result(
        raw,
        "L3-J-09",
        "environment_based_branching",
        detected=bool(qualifying),
        evidence=evidence,
        policy_resolved=(
            bool(raw.get("analysis", {}).get("anti_bot_policy_configured"))
            and normalizer is not None
        ),
    )
