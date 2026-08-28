"""명세 Signal별 HTML Analyzer와 일괄 실행 진입점."""

from __future__ import annotations

from typing import Any, Mapping

from ...models.signal import signal_result
from ...policies.detection import DetectionPolicy

from . import (
    base_url_change,
    brand_domain_mismatch,
    brand_resource_mismatch,
    credential_field,
    credential_form,
    external_post,
    form_action_domain,
    html_redirect,
)

ANALYZERS = (
    credential_form.analyze,
    credential_field.analyze,
    form_action_domain.analyze,
    external_post.analyze,
    brand_domain_mismatch.analyze,
    brand_resource_mismatch.analyze,
    html_redirect.analyze,
    base_url_change.analyze,
)

_SIGNAL_META = (
    ("L3-H-01", "credential_form"),
    ("L3-H-02", "credential_field"),
    ("L3-H-03", "form_action_domain"),
    ("L3-H-04", "external_post"),
    ("L3-H-05", "brand_domain_mismatch"),
    ("L3-H-06", "brand_resource_mismatch"),
    ("L3-H-07", "html_redirect"),
    ("L3-H-08", "base_url_change"),
)


def analyze_html(
    raw: Mapping[str, Any], document_url: str, policy: DetectionPolicy | None = None
) -> list[dict[str, Any]]:
    """L3-H-01~08을 명세 순서로 독립 실행해 결과를 모은다.

    한 Analyzer의 예외는 다른 Signal 평가를 중단시키지 않는다. HTML Source가
    잘렸다면 양성 관측은 유지할 수 있지만 음성 관측은 전체 문서 기준으로 확정할 수
    없으므로 ``error``/``detected=None``으로 변경한다.
    """
    results = []
    for analyzer, (signal_id, name) in zip(ANALYZERS, _SIGNAL_META, strict=True):
        try:
            result = analyzer(raw, document_url, policy)
            # 잘린 본문에서 '있음'은 관측할 수 있지만 '없음'은 증명할 수 없다.
            if (
                raw.get("document", {}).get("source_complete") is False
                and result.get("detected") is False
            ):
                result["status"] = "error"
                result["detected"] = None
                result["error"] = {"code": "html_analysis_incomplete"}
            results.append(result)
        except Exception as exc:
            results.append(
                signal_result(
                    signal_id,
                    "html",
                    name,
                    status="error",
                    detected=None,
                    error={
                        "code": "analyzer_failed",
                        "message": str(exc),
                        "exception": type(exc).__name__,
                    },
                )
            )
    return results


__all__ = ["ANALYZERS", "analyze_html"]
