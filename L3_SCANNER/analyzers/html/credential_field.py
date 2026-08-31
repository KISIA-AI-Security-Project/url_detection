"""L3-H-02 Credential Field: 정책에 따른 인증 입력 필드 관측."""

from __future__ import annotations

from typing import Any, Mapping

from L3_SCANNER.models.signal import signal_result
from L3_SCANNER.policies.detection import DetectionPolicy

from ._common import classify_fields, fatal_html_error


def analyze(
    raw: Mapping[str, Any], document_url: str, policy: DetectionPolicy | None = None
) -> dict[str, Any]:
    """Credential 분류 정책 결과를 필드 수·유형·식별자로 구조화한다.

    정책이 없을 때 임의로 password/email 규칙을 만들지 않고 Evidence는 빈 구조로,
    판정은 ``None``으로 유지한다.
    """
    del document_url
    fatal = fatal_html_error(raw)
    if fatal:
        return signal_result(
            "L3-H-02",
            "html",
            "credential_field",
            status="error",
            detected=None,
            error=fatal,
        )
    fields, error = classify_fields(raw, policy)
    if error:
        return signal_result(
            "L3-H-02",
            "html",
            "credential_field",
            status="error",
            detected=None,
            error=error,
        )
    evidence = {
        "field_count": len(fields),
        "field_types": sorted({field["credential_type"] for field in fields}),
        "fields": fields,
    }
    if policy is None or policy.credential_classifier is None:
        return signal_result(
            "L3-H-02",
            "html",
            "credential_field",
            status="evaluated",
            detected=None,
            evidence=evidence,
        )
    return signal_result(
        "L3-H-02",
        "html",
        "credential_field",
        status="evaluated",
        detected=bool(fields),
        evidence=evidence,
    )
