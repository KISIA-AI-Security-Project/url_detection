"""L3-H-06 Brand Resource Mismatch: 브랜드 리소스 관계의 정책 기반 관측."""

from __future__ import annotations

from typing import Any, Mapping

from L3_SCANNER.models.signal import signal_result
from L3_SCANNER.policies.detection import DetectionPolicy
from L3_SCANNER.utils.url import etld1

from ._common import brand_evidence, fatal_html_error


def _resources(raw: Mapping[str, Any]) -> list[dict[str, Any]]:
    """이미지·Favicon·URL형 Open Graph 항목을 동일한 Evidence 형태로 모은다."""
    result = [
        {
            "resource_type": "image",
            "resource_url": image.get("resource_url"),
            "resource_domain": image.get("resource_domain"),
        }
        for image in raw.get("images", [])
    ]
    favicon = raw.get("favicon")
    if favicon:
        result.append(
            {
                "resource_type": "favicon",
                "resource_url": favicon.get("resource_url"),
                "resource_domain": favicon.get("resource_domain"),
            }
        )
    for property_name, value in raw.get("open_graph", {}).items():
        if value.get("resource_url"):
            result.append(
                {
                    "resource_type": property_name,
                    "resource_url": value.get("resource_url"),
                    "resource_domain": etld1(value.get("resource_url")),
                }
            )
    return result


def analyze(
    raw: Mapping[str, Any], document_url: str, policy: DetectionPolicy | None = None
) -> dict[str, Any]:
    """브랜드·현재 도메인·리소스 목록을 정책 evaluator에 전달한다.

    리소스 호스팅은 CDN/SSO 등 정상적인 교차 도메인을 포함할 수 있으므로 Analyzer가
    자체 규칙을 만들지 않는다. evaluator가 명시적인 bool을 반환할 때만 판정한다.
    """
    fatal = fatal_html_error(raw)
    if fatal:
        return signal_result(
            "L3-H-06",
            "html",
            "brand_resource_mismatch",
            status="error",
            detected=None,
            error=fatal,
        )
    resources = _resources(raw)
    brand, current, identification, brand_error = brand_evidence(
        raw, document_url, policy
    )
    if brand_error:
        return signal_result(
            "L3-H-06",
            "html",
            "brand_resource_mismatch",
            status="error",
            detected=None,
            error=brand_error,
        )
    # 명세의 대표 단일 리소스 필드와 다중 리소스 보존 계약을 함께 제공한다.
    first = (
        resources[0]
        if resources
        else {"resource_type": None, "resource_url": None, "resource_domain": None}
    )
    evidence = {
        **first,
        "resources": resources,
        "detected_brand": brand,
        "brand_identification_sources": identification["sources"],
        "brand_identification_confidence": identification["confidence"],
        "brand_policy_provider": identification["provider"],
        "brand_policy_entity_id": identification["provider_entity_id"],
        "current_domain": current,
    }
    rules = policy.brand_resource_rules if policy is not None else None
    evaluator = rules.get("evaluator") if rules is not None else None
    detected: bool | None = None
    error = None
    if callable(evaluator):
        try:
            decision = evaluator(evidence)
            detected = decision if isinstance(decision, bool) else None
        except Exception as exc:
            error = {
                "code": "brand_resource_policy_error",
                "message": str(exc),
                "exception": type(exc).__name__,
            }
    if error:
        return signal_result(
            "L3-H-06",
            "html",
            "brand_resource_mismatch",
            status="error",
            detected=None,
            evidence=evidence,
            error=error,
        )
    return signal_result(
        "L3-H-06",
        "html",
        "brand_resource_mismatch",
        status="evaluated",
        detected=detected,
        evidence=evidence,
    )
