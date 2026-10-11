"""Script와 Credential Field의 정적 분석용 메타데이터 정규화."""

from hashlib import sha256
from typing import Any, Mapping

from L3_SCANNER.models.input import ScriptInput
from L3_SCANNER.policies.detection import DetectionPolicy


def script_metadata(script: ScriptInput) -> dict[str, Any]:
    """분석한 소스와 식별·완전성·수집 응답을 함께 보존한다."""
    digest = script.sha256
    if digest is None and script.source is not None:
        digest = sha256(script.source.encode("utf-8")).hexdigest()
    return {
        "script_id": script.script_id,
        "source": script.source,
        "type": script.type,
        "media_type": script.media_type,
        "async_script": script.async_script,
        "defer_script": script.defer_script,
        "source_url": script.source_url,
        "response": dict(script.response),
        "sha256": digest,
        "size": (
            script.size
            if script.size is not None
            else (
                len(script.source.encode("utf-8"))
                if script.source is not None
                else None
            )
        ),
        "truncated": script.truncated,
        "collection_errors": list(script.collection_errors),
    }


def credential_fields(
    html_raw: Mapping[str, Any], policy: DetectionPolicy
) -> dict[str, dict[str, Any]]:
    """DOM 순서대로 조회 대상을 선택하고 선택된 입력에만 Credential 분류를 연결한다.

    정책이 제공한 분류만 사용하며 입력값은 포함하지 않는다. id/name/내부 field_id를
    구분해 인덱싱한다. 일반 요소도 보존하므로 뒤의 민감 필드로 건너뛰지 않는다.
    """
    from L3_SCANNER.analyzers.credential_classification import classification_result

    classification = classification_result(html_raw, policy)
    by_field = {x["field_id"]: x for x in classification["fields"]}
    fields: dict[str, dict[str, Any]] = {}
    inputs = {item["field_id"]: item for item in html_raw.get("inputs", [])}
    for element in html_raw.get("dom_lookup_elements", html_raw.get("inputs", [])):
        item = inputs.get(element.get("field_id"), element)
        classified = by_field.get(item.get("field_id"), {})
        credential_type = classified.get("credential_type")
        field_id = str(item.get("field_id") or item.get("id") or item.get("name") or "")
        data = {
            "field_id": field_id,
            "credential_type": credential_type,
            "tag": element.get("tag", "input"),
            "classification_state": classified.get("state", "not_performed"),
        }
        selectors = [
            ("id:", element.get("html_id") or element.get("id")),
            ("name:", element.get("name")),
            ("tag:", data["tag"]),
        ]
        if data["tag"] == "input":
            selectors.append(("input-name:", element.get("name")))
        for prefix, selector in selectors:
            if selector:
                fields.setdefault(prefix + str(selector), data)
    return fields
