from __future__ import annotations

import httpx

from L3_SCANNER.collectors.javascript_collector import collect_external_script
from L3_SCANNER.models.input import ScriptInput
from L3_SCANNER.policies.runtime import RuntimeConfig


def _public_resolver(hostname: str, port: int) -> list[str]:
    del hostname, port
    return ["93.184.216.34"]


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
