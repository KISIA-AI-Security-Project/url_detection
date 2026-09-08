"""공통 HTTP 스냅샷을 외부 JavaScript ``ScriptInput``에 적용한다."""

from __future__ import annotations

from url_collector import CollectionPolicy, PageSnapshot

from L3_SCANNER.models.input import ScriptInput
from L3_SCANNER.policies.runtime import RuntimeConfig
from L3_SCANNER.utils.hashing import sha256_text

_JAVASCRIPT_CONTENT_TYPES = {
    "application/ecmascript",
    "application/javascript",
    "text/ecmascript",
    "text/javascript",
}
_L3_USER_AGENT = "L3-Scanner/1.0"


def script_collection_policy(runtime: RuntimeConfig) -> CollectionPolicy:
    """외부 Script 한 개에 적용할 L3 제한을 공통 Collector 프로필로 만든다."""
    return CollectionPolicy(
        request_timeout_seconds=runtime.request_timeout_seconds,
        max_redirects=runtime.max_redirects,
        max_body_bytes=runtime.max_script_bytes,
        user_agent=_L3_USER_AGENT,
    )


def apply_script_snapshot(script: ScriptInput, snapshot: PageSnapshot) -> ScriptInput:
    """수집 결과와 오류를 기존 Script 입력 객체에 구조적으로 기록한다."""
    script.collection_errors.extend(snapshot.error_dicts())
    if not snapshot.response_received:
        return script
    if snapshot.content_type not in _JAVASCRIPT_CONTENT_TYPES:
        script.collection_errors.append(
            {
                "stage": "script_collection",
                "code": "unsupported_script_content_type",
                "message": "response is not a JavaScript content type",
                "details": {"content_type": snapshot.content_type},
            }
        )
        return script

    encoding = snapshot.encoding or "utf-8"
    source = snapshot.body.decode(encoding, errors="replace")
    script.source_url = snapshot.final_url or snapshot.current_url
    script.source = source
    script.sha256 = sha256_text(source)
    script.size = len(snapshot.body)
    script.truncated = snapshot.truncated
    return script
