from __future__ import annotations

import httpx

from L3_SCANNER.collectors.page_collector import collect_page
from L3_SCANNER.policies.runtime import RuntimeConfig


def _public_resolver(hostname: str, port: int) -> list[str]:
    del hostname, port
    return ["93.184.216.34"]


def test_collect_page_follows_bounded_redirect_and_preserves_final_url() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": "/final"})
        return httpx.Response(
            200,
            headers={"content-type": "text/html; charset=utf-8"},
            content=b"<html>ok</html>",
        )

    result = collect_page(
        "https://example.com/start",
        resolver=_public_resolver,
        transport=httpx.MockTransport(handler),
    )
    assert result.document_url == "https://example.com/final"
    assert result.html.content == "<html>ok</html>"
    assert result.collection_errors == []


def test_collect_page_blocks_private_address_before_request() -> None:
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200)

    result = collect_page(
        "http://internal.example/",
        resolver=lambda hostname, port: ["127.0.0.1"],
        transport=httpx.MockTransport(handler),
    )
    assert result.html.content is None
    assert result.collection_errors[0]["code"] == "page_collection_failed"
    assert called is False


def test_collect_page_blocks_non_global_shared_address_before_request() -> None:
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200)

    result = collect_page(
        "http://shared.example/",
        resolver=lambda hostname, port: ["100.64.0.1"],
        transport=httpx.MockTransport(handler),
    )
    assert result.html.content is None
    assert result.collection_errors[0]["code"] == "page_collection_failed"
    assert called is False


def test_collect_page_truncates_body_at_configured_limit() -> None:
    result = collect_page(
        "https://example.com/",
        RuntimeConfig(max_html_bytes=4),
        resolver=_public_resolver,
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                headers={"content-type": "text/html"},
                content=b"12345678",
            )
        ),
    )
    assert result.html.content == "1234"
    assert result.html.truncated is True


def test_collect_page_preserves_unexpected_content_with_error() -> None:
    result = collect_page(
        "https://example.com/",
        resolver=_public_resolver,
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                headers={"content-type": "application/json"},
                content=b"{}",
            )
        ),
    )
    assert result.html.content == "{}"
    assert result.collection_errors[0]["code"] == "unsupported_content_type"
