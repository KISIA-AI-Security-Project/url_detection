"""HTML Analyzer의 공통 관측 도우미.

Signal별 판정은 각 ID 모듈에 남겨 추적성을 유지한다. 이 모듈은 파싱 실패 확인,
외부 정책 호출, 도메인 정규화처럼 여러 Signal이 동일하게 수행해야 할 작업만 맡는다.
"""

from __future__ import annotations

from typing import Any, Mapping

from ...policies.detection import DetectionPolicy
from ...utils.url import etld1


def fatal_html_error(raw: Mapping[str, Any]) -> dict[str, Any] | None:
    """HTML 구조를 평가할 수 없는 치명적 파싱 오류 하나를 반환한다."""
    if raw.get("document", {}).get("parse_succeeded"):
        return None
    errors = list(raw.get("errors", []))
    return (
        errors[0]
        if errors
        else {"code": "html_not_parsed", "message": "HTML was not parsed"}
    )


def classify_fields(
    raw: Mapping[str, Any], policy: DetectionPolicy | None
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """주입된 정책으로 Credential Field를 분류하고 구조적 증거만 반환한다.

    실제 필드 값은 읽거나 저장하지 않는다. 정책 부재는 오류가 아니라 미확정 상태이므로
    빈 목록과 ``error=None``을 반환하고 호출자가 ``detected=None``을 선택하게 한다.
    """
    classifier = policy.credential_classifier if policy is not None else None
    if classifier is None:
        return [], None
    classified: list[dict[str, Any]] = []
    try:
        for field in raw.get("inputs", []):
            credential_type = classifier(field)
            if credential_type:
                classified.append(
                    {
                        "field_id": field.get("field_id"),
                        "form_id": field.get("form_id"),
                        "credential_type": str(credential_type),
                    }
                )
    except Exception as exc:
        return [], {
            "code": "credential_policy_error",
            "message": str(exc),
            "exception": type(exc).__name__,
        }
    return classified, None


def normalize_expected_domain(value: str) -> str | None:
    """정책 데이터의 URL/도메인 표현을 비교 가능한 eTLD+1으로 통일한다."""
    value = value.strip().lower().rstrip(".")
    if not value:
        return None
    return etld1(value if "://" in value else f"https://{value}")


def brand_evidence(
    raw: Mapping[str, Any], document_url: str, policy: DetectionPolicy | None
) -> tuple[str | None, str | None, dict[str, Any] | None]:
    """브랜드 식별 정책에 객관적 문서 문맥을 제공하고 현재 도메인과 함께 반환한다.

    브랜드-도메인 매핑은 이 함수가 추측하지 않는다. 정책 Callable의 예외는 구조화해
    두 브랜드 Signal이 동일한 방식으로 오류를 보고하도록 한다.
    """
    current_domain = etld1(document_url)
    identifier = policy.brand_identifier if policy is not None else None
    if identifier is None:
        return None, current_domain, None
    context = {
        "document": raw.get("document", {}),
        "open_graph": raw.get("open_graph", {}),
        "images": raw.get("images", []),
        "favicon": raw.get("favicon"),
    }
    try:
        brand = identifier(context)
    except Exception as exc:
        return (
            None,
            current_domain,
            {
                "code": "brand_policy_error",
                "message": str(exc),
                "exception": type(exc).__name__,
            },
        )
    return str(brand) if brand else None, current_domain, None
