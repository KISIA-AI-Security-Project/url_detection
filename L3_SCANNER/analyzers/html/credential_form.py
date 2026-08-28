"""L3-H-01 Credential Form: 인증 필드를 포함한 Form 존재 관측."""

from __future__ import annotations

from typing import Any, Mapping

from ...models.signal import signal_result
from ...policies.detection import DetectionPolicy

from ._common import classify_fields, fatal_html_error


def analyze(
    raw: Mapping[str, Any], document_url: str, policy: DetectionPolicy | None = None
) -> dict[str, Any]:
    """분류된 Credential Field의 소속 폼을 모아 H-01 결과를 생성한다.

    필드 분류 정책이 없으면 form/input Raw는 존재해도 인증 폼 여부는 확정하지 않는다.
    폼에 속하지 않은 독립 입력 필드는 H-01 form count에 포함하지 않는다.
    """
    del document_url
    fatal = fatal_html_error(raw)
    if fatal:
        return signal_result(
            "L3-H-01",
            "html",
            "credential_form",
            status="error",
            detected=None,
            error=fatal,
        )
    fields, error = classify_fields(raw, policy)
    if error:
        return signal_result(
            "L3-H-01",
            "html",
            "credential_form",
            status="error",
            detected=None,
            error=error,
        )
    form_ids = sorted(
        {field["form_id"] for field in fields if field.get("form_id") is not None}
    )
    evidence = {"form_count": len(form_ids), "form_ids": form_ids}
    if policy is None or policy.credential_classifier is None:
        return signal_result(
            "L3-H-01",
            "html",
            "credential_form",
            status="evaluated",
            detected=None,
            evidence=evidence,
        )
    return signal_result(
        "L3-H-01",
        "html",
        "credential_form",
        status="evaluated",
        detected=bool(form_ids),
        evidence=evidence,
    )
