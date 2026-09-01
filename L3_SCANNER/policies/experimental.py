"""AWS smoke test용 임시 L3 탐지 정책.

이 프리셋은 ``docs/L3_SPEC.md``에서 Open으로 남은 정책을 제품 판정 규칙으로
확정하지 않는다. Parser·Analyzer의 전체 경로를 실행하기 위한 명시적인
테스트 값이며, 운영 악성/정상 판정에 사용하면 안 된다.
"""

from __future__ import annotations

from typing import Any, Mapping

from .detection import DetectionPolicy

EXPERIMENTAL_POLICY_NAME = "aws-smoke-v1"

_BRAND_EXPECTED_DOMAINS: dict[str, tuple[str, ...]] = {
    "pettrip": ("chapchu.site",),
}


def _credential_classifier(field: Mapping[str, Any]) -> str | None:
    """임시 attribute 규칙으로 password/email/username 필드를 분류한다."""
    field_type = str(field.get("type") or "").strip().lower()
    if field_type in {"password", "email"}:
        return field_type

    identifiers = " ".join(
        str(field.get(key) or "").strip().lower()
        for key in ("html_id", "name", "placeholder", "autocomplete")
    )
    if any(token in identifiers for token in ("username", "user_name", "login")):
        return "username"
    return None


def _brand_identifier(context: Mapping[str, Any]) -> str | None:
    """AWS 테스트 대상의 문서 제목에서 PetTrip 브랜드를 식별한다."""
    document = context.get("document") or {}
    title = str(document.get("title") or "").lower()
    return "pettrip" if "pettrip" in title else None


def _brand_resource_evaluator(evidence: Mapping[str, Any]) -> bool:
    """임시 공식 Domain 밖의 Brand Resource를 mismatch로 본다."""
    brand = evidence.get("detected_brand")
    expected = set(_BRAND_EXPECTED_DOMAINS.get(str(brand), ()))
    current = evidence.get("current_domain")
    allowed = expected | ({str(current)} if current else set())
    return any(
        resource.get("resource_domain") is not None
        and resource.get("resource_domain") not in allowed
        for resource in evidence.get("resources", [])
    )


def _branch_behavior_normalizer(branch: Mapping[str, Any]) -> str:
    """정적 Branch 관측 목록을 재현 가능한 비교 문자열로 변환한다."""
    return repr(branch.get("observations", []))


def experimental_detection_policy() -> DetectionPolicy:
    """Open Policy 필드를 모두 채운 AWS smoke test용 프리셋을 만든다."""
    return DetectionPolicy(
        credential_classifier=_credential_classifier,
        brand_identifier=_brand_identifier,
        brand_expected_domains=_BRAND_EXPECTED_DOMAINS,
        brand_resource_rules={"evaluator": _brand_resource_evaluator},
        dynamic_execution_apis=frozenset({"eval", "Function"}),
        decode_methods=frozenset({"atob", "decodeURIComponent", "unescape"}),
        network_apis=frozenset(
            {"fetch", "navigator.sendBeacon", "XMLHttpRequest.open"}
        ),
        redirect_apis=frozenset(
            {
                "location.replace",
                "location.assign",
                "location.href",
                "window.location",
            }
        ),
        anti_bot_properties=frozenset(
            {
                "navigator.webdriver",
                "navigator.plugins",
                "navigator.languages",
                "window.chrome",
            }
        ),
        branch_behavior_normalizer=_branch_behavior_normalizer,
    )


__all__ = ["EXPERIMENTAL_POLICY_NAME", "experimental_detection_policy"]
