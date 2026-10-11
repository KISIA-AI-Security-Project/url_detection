"""모든 HTML/JavaScript Analyzer가 공유하는 Signal 결과 모델."""

from __future__ import annotations

from typing import Any, Literal

TECHNICAL_PREDICATES = {
    "L3-H-01": "A form has fields classified by the configured credential policy",
    "L3-H-02": "Fields are classified by the configured credential policy",
    "L3-H-03": "Recorded form and action-domain relationships",
    "L3-H-04": "A recorded native form POST target is external under configured domain comparison",
    "L3-H-05": "Policy-identified brand differs from configured expected-domain reference",
    "L3-H-06": "Configured resource evaluator returned a decision on the supplied brand/resource evidence",
    "L3-H-07": "Recorded HTML redirect declaration",
    "L3-H-08": "Recorded base URL affects relative destination resolution",
    "L3-J-01": "Static source contains configured dynamic-execution API usage",
    "L3-J-02": "Recorded decode lineage connects to a static execution API event",
    "L3-J-03": "Static source contains configured script-injection structure",
    "L3-J-04": "Static source records configured network destinations",
    "L3-J-05": "Static source reads policy-classified credential inputs",
    "L3-J-06": "Recorded credential source-to-external-network payload relationship",
    "L3-J-07": "Static source contains configured navigation API usage",
    "L3-J-08": "Static source inspects configured environment properties",
    "L3-J-09": "Configured normalizer finds different behaviors in comparable environment branches",
}

SignalStatus = Literal["evaluated", "not_applicable", "error"]


def signal_result(
    signal_id: str,
    scanner: Literal["html", "javascript"],
    name: str,
    *,
    status: SignalStatus,
    detected: bool | None,
    evidence: dict[str, Any] | None = None,
    error: dict[str, Any] | str | None = None,
    limitations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """미확정·오류 상태를 음성 결과로 축소하지 않고 Signal을 생성한다.

    ``evaluated``가 아닌 상태에서는 조건을 확정할 수 없으므로 ``detected``가
    반드시 ``None``이어야 한다. 이 검증은 새로운 Analyzer가 오류를 ``False``로
    잘못 표현하는 것을 조기에 막는다.
    """
    if status != "evaluated" and detected is not None:
        raise ValueError("non-evaluated signals must use detected=None")
    result: dict[str, Any] = {
        "id": signal_id,
        "technical_scope": {
            "predicate": TECHNICAL_PREDICATES.get(signal_id),
            "certainty": "technical_observation_only",
            "url_verdict": "not_assessed",
            "limits": "Policy classification and static syntax/data-flow evidence do not establish runtime execution, intent, ownership or maliciousness. Multiple findings may share the same source.",
        },
        "scanner": scanner,
        "name": name,
        "status": status,
        "detected": detected,
        "evidence": evidence or {},
        "error": error,
    }
    if limitations:
        result["limitations"] = limitations
    return result
