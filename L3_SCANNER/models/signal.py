"""모든 HTML/JavaScript Analyzer가 공유하는 Signal 결과 모델."""

from __future__ import annotations

from typing import Any, Literal

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
) -> dict[str, Any]:
    """미확정·오류 상태를 음성 결과로 축소하지 않고 Signal을 생성한다.

    ``evaluated``가 아닌 상태에서는 조건을 확정할 수 없으므로 ``detected``가
    반드시 ``None``이어야 한다. 이 검증은 새로운 Analyzer가 오류를 ``False``로
    잘못 표현하는 것을 조기에 막는다.
    """
    if status != "evaluated" and detected is not None:
        raise ValueError("non-evaluated signals must use detected=None")
    return {
        "id": signal_id,
        "scanner": scanner,
        "name": name,
        "status": status,
        "detected": detected,
        "evidence": evidence or {},
        "error": error,
    }
