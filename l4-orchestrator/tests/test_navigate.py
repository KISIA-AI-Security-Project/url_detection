from sdk_tool_checks import run_native_steps
import asyncio
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from threading import Thread
import time

import pytest
from pydantic import ValidationError

playwright = pytest.importorskip("playwright.async_api", reason="Install the browser extra to run browser tests")

from l4_orchestrator.tools.navigate import NavigateTool
from l4_orchestrator.ports import Authorization


@pytest.fixture(scope="module")
def site():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/destination")
                self.end_headers()
                return
            if self.path == "/slow":
                time.sleep(1)
            self.send_response(404 if self.path == "/missing" else 200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            try:
                self.wfile.write(b"<!doctype html><title>Navigation check</title><p>Loaded</p>")
            except OSError:
                pass  # The timed-out test may have already closed its browser.

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()
    thread.join()


def action(url):
    return {"action_id": "navigate-check", "tool": "navigate", "target": {"url": url},
            "params": {"wait_until": "domcontentloaded"},
            "context": {"job_id": "local-check", "scenario_id": "navigation",
                        "step_id": "open-page", "state_id": None}}


async def with_page(site, check):
    async with playwright.async_playwright() as runtime:
        browser = await runtime.chromium.launch(channel=os.environ.get("L4_BROWSER_CHANNEL"), headless=True)
        try:
            context = await browser.new_context(service_workers="block", accept_downloads=False)

            async def local_only(route):
                if route.request.url.startswith(site + "/"):
                    await route.continue_()
                else:
                    await route.abort()

            await context.route("**/*", local_only)
            page = await context.new_page()
            # Let the new viewport's first resize/render finish before tests observe it.
            # PageState correctly rejects a snapshot if that notification arrives mid-read.
            await page.evaluate("() => new Promise(requestAnimationFrame)")
            await check(page)
        finally:
            await browser.close()


def make_tool(page, site, timeout_ms=3000):
    return NavigateTool(page, timeout_ms=timeout_ms, authorize_url=lambda url: Authorization(
        url.startswith(site + "/") and not url.endswith("/blocked"), "Controlled page only"))


@pytest.mark.parametrize("path, final_path, http_status", [
    ("/", "/", 200), ("/redirect", "/destination", 200), ("/missing", "/missing", 404),
])
def test_actual_navigation_and_http_error_page(site, path, final_path, http_status):
    async def check(page):
        result = await make_tool(page, site).execute(action(site + path))
        assert result["status"] == "success" and result["error"] is None
        assert result["result"] == {"requested_url": site + path, "current_url": site + final_path,
                                    "http_status": http_status}
        assert page.url == result["result"]["current_url"]
        assert await page.title() == "Navigation check"
        assert result["after_state_id"] is None and result["observer_refs"] == {"l2": [], "l3": []}
        assert not page.is_closed()
    asyncio.run(with_page(site, check))


def test_invalid_blocked_and_unsupported_inputs_do_not_navigate(site):
    async def check(page):
        tool = make_tool(page, site)
        for url, status, code in [("javascript:alert(1)", "failed", "INVALID_URL"),
                                  (site + "/blocked", "blocked", "BLOCKED_URL")]:
            result = await tool.execute(action(url))
            assert result["status"] == status and result["error"]["code"] == code
            assert result["result"] is None and page.url == "about:blank"
        request = action(site + "/")
        request["params"]["save_everything"] = True
        with pytest.raises(ValidationError):
            await tool.execute(request)
        assert page.url == "about:blank"
    asyncio.run(with_page(site, check))


def test_timeout_and_closed_page_do_not_claim_observed_final_state(site):
    async def check(page):
        tool = make_tool(page, site, timeout_ms=50)
        result = await tool.execute(action(site + "/slow"))
        assert result["status"] == "timeout" and result["error"]["code"] == "NAVIGATION_TIMEOUT"
        assert result["result"] is None and result["after_state_id"] is None
        assert not page.is_closed()  # The caller owns cleanup, including a navigation still in flight.
        await page.close()
        result = await tool.execute(action(site + "/"))
        assert result["status"] == "failed" and result["error"]["code"] == "PAGE_CLOSED"
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("path, expected_status", [("/redirect", "success"), ("/blocked", "blocked")])
def test_sdk_receives_the_action_result(site, path, expected_status):
    async def check(page):
        proof = await run_native_steps({"navigate": make_tool(page, site)},
                                       [("navigate", action(site + path))])
        assert proof.results[0]["status"] == expected_status
        assert len(proof.actions) == 1
    asyncio.run(with_page(site, check))
