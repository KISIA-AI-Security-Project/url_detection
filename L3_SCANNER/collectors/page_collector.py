"""제한 HTTP 클라이언트로 HTML 페이지를 수집해 공통 L3 입력을 만든다."""

from __future__ import annotations

from typing import Any

import httpx

from L3_SCANNER.models.input import HTMLInput, L3Input
from L3_SCANNER.policies.runtime import RuntimeConfig
from .http_client import Resolver, bounded_get, collection_error, system_resolver

_HTML_CONTENT_TYPES = {"text/html", "application/xhtml+xml"}


def collect_page(
    url: str,
    runtime: RuntimeConfig | None = None,
    *,
    resolver: Resolver = system_resolver,
    transport: httpx.BaseTransport | None = None,
) -> L3Input:
    """외부 스크립트 Source를 가져오지 않고 HTML 페이지 하나를 수집한다.

    실패해도 예외로 전체 스캔을 중단하지 않고 ``content=None``과 구조화 오류가 든
    ``L3Input``을 반환해 downstream이 '미수집'과 '관측 없음'을 구분하게 한다.
    """
    runtime = runtime or RuntimeConfig()
    errors: list[dict[str, Any]] = []
    try:
        response = bounded_get(
            url,
            max_bytes=runtime.max_html_bytes,
            runtime=runtime,
            resolver=resolver,
            transport=transport,
        )
        errors.extend(response.errors)
    except (httpx.HTTPError, ValueError, OSError) as exc:
        errors.append(
            collection_error("collection", "page_collection_failed", str(exc), url=url)
        )
        return L3Input(
            original_url=url,
            document_url=url,
            html=HTMLInput(content=None),
            collection_errors=errors,
        )

    if response.content_type not in _HTML_CONTENT_TYPES:
        errors.append(
            collection_error(
                "collection",
                "unsupported_content_type",
                "response is not an HTML content type",
                content_type=response.content_type,
            )
        )

    encoding = response.encoding or "utf-8"
    content = response.body.decode(encoding, errors="replace")
    return L3Input(
        original_url=url,
        document_url=response.url,
        html=HTMLInput(
            content=content,
            content_type=response.content_type,
            encoding=encoding,
            truncated=response.truncated,
        ),
        collection_errors=errors,
    )
