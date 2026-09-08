"""공통 페이지 스냅샷을 명세의 ``L3Input``으로 변환한다."""

from __future__ import annotations

from url_collector import CollectionPolicy, PageSnapshot

from L3_SCANNER.models.input import HTMLInput, L3Input
from L3_SCANNER.policies.runtime import RuntimeConfig

_HTML_CONTENT_TYPES = {"text/html", "application/xhtml+xml"}
_L3_USER_AGENT = "L3-Scanner/1.0"


def page_collection_policy(runtime: RuntimeConfig) -> CollectionPolicy:
    """L3 독립 실행의 기존 자원 제한을 공통 Collector 프로필로 만든다."""
    return CollectionPolicy(
        request_timeout_seconds=runtime.request_timeout_seconds,
        max_redirects=runtime.max_redirects,
        max_body_bytes=runtime.max_html_bytes,
        user_agent=_L3_USER_AGENT,
    )


def to_l3_input(snapshot: PageSnapshot) -> L3Input:
    """추가 네트워크 요청 없이 동일 응답 본문과 오류를 ``L3Input``에 보존한다."""
    errors = snapshot.error_dicts()
    content: str | None = None
    encoding = snapshot.encoding or "utf-8"
    if snapshot.response_received:
        content = snapshot.body.decode(encoding, errors="replace")
        if snapshot.content_type not in _HTML_CONTENT_TYPES:
            errors.append(
                {
                    "stage": "collection",
                    "code": "unsupported_content_type",
                    "message": "response is not an HTML content type",
                    "details": {"content_type": snapshot.content_type},
                }
            )

    return L3Input(
        original_url=snapshot.original_url,
        document_url=snapshot.final_url or snapshot.current_url,
        html=HTMLInput(
            content=content,
            content_type=snapshot.content_type,
            encoding=encoding if snapshot.response_received else None,
            truncated=snapshot.truncated,
        ),
        collection_errors=errors,
    )
