"""L3-H-05 Brand-Domain Mismatch: 식별 브랜드와 현재 도메인의 정책 비교."""

from __future__ import annotations

from typing import Any, Mapping

from L3_SCANNER.models.signal import signal_result
from L3_SCANNER.policies.detection import DetectionPolicy

from ._common import brand_evidence, fatal_html_error, normalize_expected_domain


def analyze(
    raw: Mapping[str, Any], document_url: str, policy: DetectionPolicy | None = None
) -> dict[str, Any]:
    """외부 정책이 식별한 브랜드의 공식 도메인 집합과 현재 eTLD+1을 비교한다.

    브랜드 식별 실패, 데이터셋 부재, 미등록 브랜드, 비교 불가 URL 중 하나라도 있으면
    불일치를 음성으로 간주하지 않고 ``detected=None``을 유지한다.
    """
    fatal = fatal_html_error(raw)
    if fatal:
        return signal_result(
            "L3-H-05",
            "html",
            "brand_domain_mismatch",
            status="error",
            detected=None,
            error=fatal,
        )
    brand, current, identification, error = brand_evidence(raw, document_url, policy)
    if error:
        return signal_result(
            "L3-H-05",
            "html",
            "brand_domain_mismatch",
            status="error",
            detected=None,
            error=error,
        )
    configured = policy.brand_expected_domains if policy is not None else None
    expected = (
        list(configured.get(brand, ()))
        if configured is not None and brand is not None
        else []
    )
    evidence = {
        "detected_brand": brand,
        "brand_identification_sources": identification["sources"],
        "brand_identification_confidence": identification["confidence"],
        "brand_policy_provider": identification["provider"],
        "brand_policy_entity_id": identification["provider_entity_id"],
        "current_domain": current,
        "expected_domains": expected,
    }
    limitations = list(identification["limitations"])
    if configured is None:
        limitations.append({"code": "brand_domain_reference_not_configured"})
    elif brand is not None and brand not in configured:
        limitations.append({"code": "brand_absent_from_domain_reference", "brand": brand})
    if current is None:
        limitations.append({"code": "brand_comparison_domain_unresolved", "document_url": document_url})
    detected: bool | None = None
    if brand is not None and configured is not None and brand in configured and current is not None:
        normalized = {
            domain
            for value in expected
            if (domain := normalize_expected_domain(value)) is not None
        }
        detected = current not in normalized if normalized else None
        if not normalized:
            limitations.append({"code": "brand_domain_reference_empty" if not expected else "brand_domain_reference_invalid", "brand": brand})
    return signal_result(
        "L3-H-05",
        "html",
        "brand_domain_mismatch",
        status="evaluated",
        detected=detected,
        evidence=evidence,
        limitations=limitations,
    )
