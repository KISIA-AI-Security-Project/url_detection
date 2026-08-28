"""L3-H-07 HTML Redirect: 유효한 Meta Refresh 이동 관측."""

from __future__ import annotations

from typing import Any, Mapping

from ...models.signal import signal_result
from ...policies.detection import DetectionPolicy

from ._common import fatal_html_error


def analyze(
    raw: Mapping[str, Any], document_url: str, policy: DetectionPolicy | None = None
) -> dict[str, Any]:
    """공유 Parser가 만든 Meta Refresh 구조의 유효성을 H-07로 변환한다.

    실제 이동을 수행하거나 목적지의 위험도를 판단하지 않는다. 지연시간과 원문은
    downstream이 이동 특성을 재검토할 수 있도록 Evidence에 보존한다.
    """
    del document_url, policy
    fatal = fatal_html_error(raw)
    if fatal:
        return signal_result(
            "L3-H-07",
            "html",
            "html_redirect",
            status="error",
            detected=None,
            error=fatal,
        )
    refresh = raw.get("meta_refresh")
    evidence = {
        "target_url": refresh.get("target_url") if refresh else None,
        "delay_seconds": refresh.get("delay_seconds") if refresh else None,
        "raw_content": refresh.get("raw_content") if refresh else None,
    }
    return signal_result(
        "L3-H-07",
        "html",
        "html_redirect",
        status="evaluated",
        detected=bool(refresh and refresh.get("valid")),
        evidence=evidence,
    )
