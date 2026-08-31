"""L3-H-04 External POST: 외부 등록 도메인으로 향하는 POST Form 관측."""

from __future__ import annotations

from typing import Any, Mapping

from L3_SCANNER.models.signal import signal_result
from L3_SCANNER.policies.detection import DetectionPolicy
from L3_SCANNER.utils.url import etld1

from ._common import classify_fields, fatal_html_error


def analyze(
    raw: Mapping[str, Any], document_url: str, policy: DetectionPolicy | None = None
) -> dict[str, Any]:
    """POST 폼의 목적지를 현재 문서 eTLD+1과 비교한다.

    Credential 여부는 보조 Evidence이며 H-04의 필수 외부 POST 판단과 분리한다.
    목적지 또는 현재 도메인을 계산할 수 없는 폼이 있으면 음성으로 확정하지 않는다.
    """
    fatal = fatal_html_error(raw)
    if fatal:
        return signal_result(
            "L3-H-04",
            "html",
            "external_post",
            status="error",
            detected=None,
            error=fatal,
        )
    posts = [
        form
        for form in raw.get("forms", [])
        if str(form.get("method", "")).lower() == "post"
    ]
    if not posts:
        return signal_result(
            "L3-H-04",
            "html",
            "external_post",
            status="not_applicable",
            detected=None,
            evidence={"posts": []},
        )
    classified, classification_error = classify_fields(raw, policy)
    # Credential 정책 실패는 목적지 비교 자체를 막지 않는다. 보조 Evidence만
    # 미확정으로 두고 분류 오류는 Signal error 필드에 보존한다.
    if classification_error:
        classified = []
    credential_forms = {
        field["form_id"] for field in classified if field.get("form_id") is not None
    }
    credential_known = (
        policy is not None
        and policy.credential_classifier is not None
        and not classification_error
    )
    current = etld1(document_url)
    observations = []
    for form in posts:
        destination = form.get("action_etld1")
        external = (
            destination != current
            if destination is not None and current is not None
            else None
        )
        observations.append(
            {
                "form_id": form.get("form_id"),
                "destination_url": form.get("action_url"),
                "destination_etld1": destination,
                "external": external,
                "credential_form": (
                    form.get("form_id") in credential_forms
                    if credential_known
                    else None
                ),
            }
        )
    external_posts = [post for post in observations if post["external"] is True]
    # 단일 필드 호환성을 위해 대표 항목을 유지하되 모든 폼은 posts에 보존한다.
    selected = external_posts[0] if external_posts else observations[0]
    evidence = {
        "destination_url": selected["destination_url"] if external_posts else None,
        "destination_etld1": selected["destination_etld1"] if external_posts else None,
        "credential_form": selected["credential_form"] if external_posts else None,
        "posts": observations,
    }
    if external_posts:
        detected: bool | None = True
    elif any(post["external"] is None for post in observations):
        detected = None
    else:
        detected = False
    return signal_result(
        "L3-H-04",
        "html",
        "external_post",
        status="evaluated",
        detected=detected,
        evidence=evidence,
        error=classification_error,
    )
