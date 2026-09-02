"""JavaScript Signal의 공통 상태 처리 도우미.

어떤 이벤트가 Signal 조건인지에 대한 판단은 각 ID 모듈에 남긴다. 이 모듈은 Source
완전성, Parser 가용성, 정책 설정 여부를 공통 상태 의미로 변환하는 역할만 한다.
"""

from __future__ import annotations

from typing import Any, Mapping

from L3_SCANNER.models.signal import signal_result


def result(
    raw: Mapping[str, Any],
    signal_id: str,
    name: str,
    *,
    detected: bool | None,
    evidence: dict[str, Any],
    policy_resolved: bool = True,
) -> dict[str, Any]:
    """관측 판정과 분석 완전성을 결합해 올바른 Signal 상태를 만든다.

    양성 이벤트는 일부 Source만 분석했어도 실제 관측으로 유지할 수 있다. 반면 이벤트가
    없을 때 정책·Parser·Source가 불완전하면 ``False``가 아니라 ``None``을 반환한다.
    """
    scripts = raw.get("scripts", [])
    analysis = raw.get("analysis", {})
    if not scripts:
        return signal_result(
            signal_id,
            "javascript",
            name,
            status="not_applicable",
            detected=None,
            evidence=evidence,
        )
    if detected is True:
        return signal_result(
            signal_id,
            "javascript",
            name,
            status="evaluated",
            detected=True,
            evidence=evidence,
        )
    if not policy_resolved:
        return signal_result(
            signal_id,
            "javascript",
            name,
            status="evaluated",
            detected=None,
            evidence=evidence,
            error={"code": "detection_policy_unresolved"},
        )
    if int(analysis.get("parsed_script_count", 0)) == 0:
        return signal_result(
            signal_id,
            "javascript",
            name,
            status="error",
            detected=None,
            evidence=evidence,
            error={"code": "javascript_analysis_unavailable"},
        )
    if not bool(analysis.get("source_complete", False)) and detected is not True:
        return signal_result(
            signal_id,
            "javascript",
            name,
            status="error",
            detected=None,
            evidence=evidence,
            error={"code": "javascript_analysis_incomplete"},
        )
    return signal_result(
        signal_id,
        "javascript",
        name,
        status="evaluated",
        detected=detected,
        evidence=evidence,
    )


def unique(values: list[Any]) -> list[Any]:
    """Evidence 값의 최초 관측 순서를 유지하며 중복 제거한다."""
    result = []
    for value in values:
        if value not in result:
            result.append(value)
    return result
