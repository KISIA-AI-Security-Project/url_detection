"""Script와 Credential Field의 정적 분석용 메타데이터 정규화."""

from hashlib import sha256
from typing import Any, Mapping

from L3_SCANNER.models.input import ScriptInput
from L3_SCANNER.policies.detection import DetectionPolicy


def script_metadata(script: ScriptInput) -> dict[str, Any]:
    """Source 본문을 복제하지 않고 식별·완전성 메타데이터만 만든다."""
    digest = script.sha256
    if digest is None and script.source is not None:
        digest = sha256(script.source.encode("utf-8")).hexdigest()
    return {
        "script_id": script.script_id,
        "type": script.type,
        "source_url": script.source_url,
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
    """DOM 조회 selector를 Credential Field 구조 정보에 연결한다.

    정책이 제공한 분류만 사용하며 입력값은 포함하지 않는다. id/name/내부 field_id를
    모두 인덱싱해 제한된 DOM 조회 패턴에서 같은 필드를 찾을 수 있게 한다.
    """
    fields: dict[str, dict[str, Any]] = {}
    for item in html_raw.get("inputs", []):
        credential_type = item.get("credential_type")
        if credential_type is None and policy.credential_classifier is not None:
            credential_type = policy.credential_classifier(item)
        if not credential_type:
            continue
        field_id = str(item.get("field_id") or item.get("id") or item.get("name") or "")
        data = {"field_id": field_id, "credential_type": str(credential_type)}
        for selector in (item.get("id"), item.get("name"), item.get("field_id")):
            if selector:
                fields[str(selector)] = data
    return fields
