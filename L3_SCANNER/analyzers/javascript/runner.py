"""명세 ID별 JavaScript Signal Analyzer 등록과 일괄 실행 진입점."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Mapping

from L3_SCANNER.models.signal import signal_result
from L3_SCANNER.policies.detection import DetectionPolicy

from .anti_bot_headless_detection import analyze as analyze_j08
from .credential_access import analyze as analyze_j05
from .credential_exfiltration import analyze as analyze_j06
from .dynamic_code_execution import analyze as analyze_j01
from .dynamic_redirect import analyze as analyze_j07
from .dynamic_script_injection import analyze as analyze_j03
from .environment_based_branching import analyze as analyze_j09
from .network_destination import analyze as analyze_j04
from .obfuscation_decode_chain import analyze as analyze_j02

Analyzer = Callable[[Mapping[str, Any], DetectionPolicy | None], dict[str, Any]]


def _without_policy(
    analyzer: Callable[[Mapping[str, Any]], dict[str, Any]],
) -> Analyzer:
    """정책 인자가 필요 없는 Analyzer를 공통 호출 시그니처로 감싼다."""

    def call(raw: Mapping[str, Any], policy: DetectionPolicy | None) -> dict[str, Any]:
        """공통 정책 인자를 버리고 Raw 전용 Analyzer를 호출한다."""
        del policy
        return analyzer(raw)

    return call


ANALYZERS: tuple[tuple[str, str, Analyzer], ...] = (
    ("L3-J-01", "dynamic_code_execution", _without_policy(analyze_j01)),
    ("L3-J-02", "obfuscation_decode_chain", _without_policy(analyze_j02)),
    ("L3-J-03", "dynamic_script_injection", _without_policy(analyze_j03)),
    ("L3-J-04", "network_destination", _without_policy(analyze_j04)),
    ("L3-J-05", "credential_access", _without_policy(analyze_j05)),
    ("L3-J-06", "credential_exfiltration", _without_policy(analyze_j06)),
    ("L3-J-07", "dynamic_redirect", _without_policy(analyze_j07)),
    ("L3-J-08", "anti_bot_headless_detection", _without_policy(analyze_j08)),
    ("L3-J-09", "environment_based_branching", analyze_j09),
)


def analyze_javascript(
    raw: Mapping[str, Any], policy: DetectionPolicy | None = None
) -> list[dict[str, Any]]:
    """L3-J-01~09를 순서대로 독립 실행해 Signal 목록을 만든다.

    각 Analyzer 예외를 개별 오류 Signal로 격리하여 한 기능의 실패가 다른 Raw
    Observation과 Signal을 숨기지 않게 한다.
    """
    results = []
    for signal_id, name, analyzer in ANALYZERS:
        try:
            result = analyzer(raw, policy)
        except Exception as exc:
            result = signal_result(
                signal_id,
                "javascript",
                name,
                status="error",
                detected=None,
                error={
                    "code": "analyzer_failed",
                    "message": str(exc),
                    "exception": type(exc).__name__,
                },
            )
        results.append(result)
    return results


__all__ = [
    "analyze_j01",
    "analyze_j02",
    "analyze_j03",
    "analyze_j04",
    "analyze_j05",
    "analyze_j06",
    "analyze_j07",
    "analyze_j08",
    "analyze_j09",
    "analyze_javascript",
    "ANALYZERS",
]
