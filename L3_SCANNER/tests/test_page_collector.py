from __future__ import annotations

import httpx

from L3_SCANNER.collectors.page_collector import collect_external_script, collect_page
from L3_SCANNER.models.input import ScriptInput
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


def test_external_script_is_not_fetched_without_explicit_policy() -> None:
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, content=b"alert(1)")

    script = collect_external_script(
        ScriptInput("script-1", "external", source_url="https://cdn.example/a.js"),
        RuntimeConfig(fetch_external_scripts=False),
        resolver=_public_resolver,
        transport=httpx.MockTransport(handler),
    )
    assert script.source is None
    assert called is False


def test_external_script_fetch_is_bounded_when_explicitly_enabled() -> None:
    script = collect_external_script(
        ScriptInput("script-1", "external", source_url="https://cdn.example/a.js"),
        RuntimeConfig(fetch_external_scripts=True, max_script_bytes=4),
        resolver=_public_resolver,
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                headers={"content-type": "application/javascript"},
                content=b"12345678",
            )
        ),
    )
    assert script.source == "1234"
    assert script.truncated is True
    assert script.sha256 is not None
