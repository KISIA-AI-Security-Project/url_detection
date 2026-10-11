from page_query_support import make_query_tool
from sdk_tool_checks import run_native_steps
"""Actual Enter delivery, its limited meaning, and the existing execution connection."""
import asyncio
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from threading import Thread
from urllib.parse import parse_qs

import pytest
from pydantic import ValidationError

pytest.importorskip("playwright.async_api")
from playwright.async_api import Error, Keyboard

from l4_orchestrator.elements import ElementRegistry
from l4_orchestrator.page_events import PageEvents
from l4_orchestrator.page_state import PageState, PageStateError
from l4_orchestrator.ports import Authorization
from l4_orchestrator.tools.fill import FillTool, _PRESETS
from l4_orchestrator.tools.press_key import PressKeyTool
from test_interactable_elements import query, setup
from test_navigate import site, with_page
from test_page_state import wait_for_invalidation


def action(element_id, state_id):
    return {"action_id": "enter-check", "tool": "press_key", "target": {"element_id": element_id},
            "params": {"key": "Enter"},
            "context": {"job_id": "local-check", "scenario_id": "keyboard", "step_id": "enter",
                        "state_id": state_id}}


async def observed(page, html, *, timeout_ms=3000, on_event=None):
    state, registry, queries = await setup(page, html)
    controls = (await queries.execute(query(visible_only=False)))["result"]
    delivered = []
    events = PageEvents(state, on_event=on_event or (
        lambda event, event_page: delivered.append((event, event_page))))
    request = action(controls["elements"][0]["element_id"], controls["state_id"])
    await page.evaluate("window.keys=[]; document.addEventListener('keydown', e => window.keys.push(e.key))")
    return state, PressKeyTool(registry, timeout_ms=timeout_ms, page_events=events), request, delivered


@pytest.fixture
def submission_site():
    received = []

    class Handler(BaseHTTPRequestHandler):
        def respond(self, html):
            raw = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            self.respond('<!doctype html><title>Enter form</title><form action="/submit" method="post">'
                         '<label>Email<input name="email" type="email"></label></form>')

        def do_POST(self):
            raw = self.rfile.read(int(self.headers["Content-Length"]))
            received.append({"method": "POST", "path": self.path, "body_utf8": raw.decode("utf-8"),
                             "cookie": self.headers.get("Cookie")})
            self.respond('<!doctype html><title>After Enter</title><p>서버가 입력을 받았습니다.</p>')

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}", received
    server.shutdown()
    server.server_close()
    thread.join()


def test_fill_refresh_enter_post_and_next_sdk_input(submission_site, tmp_path):
    origin, received = submission_site

    async def check(page):
        await page.goto(origin + "/form")
        await page.evaluate("document.cookie='enter_session=kept'; new Promise(requestAnimationFrame)")
        source = await page.content()
        state = PageState(page, timeout_ms=3000)
        registry = ElementRegistry(state, timeout_ms=3000)
        queries = make_query_tool(registry.state, elements=registry)
        events_received = []
        events = PageEvents(state, on_event=lambda event, event_page: events_received.append(event))
        tool = PressKeyTool(registry, timeout_ms=3000, page_events=events)
        initial = (await queries.execute(query()))["result"]
        fill_request = {**action(initial["elements"][0]["element_id"], initial["state_id"]),
                        "action_id": "fill-before-enter", "tool": "fill",
                        "params": {"value_type": "dummy_email", "clear_first": True}}
        filled = await FillTool(registry, timeout_ms=3000, page_events=events).execute(fill_request)
        assert filled["status"] == "success" and received == []
        old = await tool.execute(action(initial["elements"][0]["element_id"], initial["state_id"]))
        assert old["error"]["code"] == "TARGET_STALE" and old["result"]["pressed"] is False
        assert received == []
        current = (await queries.execute(query()))["result"]
        press_request = action(current["elements"][0]["element_id"], current["state_id"])
        content_request = {**press_request, "action_id": "read-after-enter", "tool": "get_page_state",
                           "target": None, "params": {"include": ["text"]},
                           "context": {**press_request["context"], "state_id": None}}
        content = make_query_tool(state, elements=registry, timeout_ms=3000, max_text_bytes=2000,
                                    max_links=10, max_links_bytes=2000)

        async def read_after_enter(previous):
            # Wait for this fixture's known response; press_key itself does not.
            await page.wait_for_url(origin + "/submit", wait_until="load")
            await page.evaluate("() => new Promise(requestAnimationFrame)")
            return content_request

        proof = await run_native_steps({"press_key": tool, "get_page_state": content}, [
            ("press_key", press_request), ("get_page_state", read_after_enter)])
        result, later = proof.results
        assert result["status"] == "success" and result["result"]["pressed"] is True, result
        assert result["before_state_id"] == current["state_id"] and result["after_state_id"] is None
        assert "submitted" not in result["result"]
        assert later["status"] == "success" and "서버가 입력을 받았습니다." in json.dumps(later, ensure_ascii=False)
        assert len(received) == 1 and received[0]["path"] == "/submit"
        assert parse_qs(received[0]["body_utf8"]) == {"email": [_PRESETS["dummy_email"]]}
        assert received[0]["cookie"] == "enter_session=kept"
        assert later["result"]["page_id"] == initial["page_id"] and len(page.context.pages) == 1
        assert any(event["kind"] == "navigation" and event["url"] == origin + "/submit" for event in events_received)
        (tmp_path / "sdk-evidence.json").write_text(json.dumps({
            "source_html": source, "fill_input": fill_request, "fill_result": filled,
            "stale_press_result": old, "element_query": current,
            "prepared_inputs": proof.prepared_inputs, "results": proof.results,
            "server_received": received, "actual_model_inputs": proof.model_inputs,
            "same_page_and_session": True}, ensure_ascii=False, indent=2), encoding="utf-8")
    asyncio.run(with_page(origin, check))


@pytest.mark.parametrize("behavior", ["prevent_submission", "textarea_newline"])
def test_completed_enter_does_not_mean_submission(site, behavior):
    async def check(page):
        html = ('<form onsubmit="window.submits++;return false"><input onkeydown="event.preventDefault()"></form>'
                if behavior == "prevent_submission" else '<textarea></textarea>')
        state, tool, request, delivered = await observed(page, html)
        await page.evaluate("window.submits=0")
        result = await tool.execute(request)
        assert result["status"] == "success" and result["result"]["pressed"] is True
        assert await page.evaluate("window.keys") == ["Enter"] and await page.evaluate("window.submits") == 0
        if behavior == "textarea_newline":
            assert await page.locator("textarea").input_value() == "\n"
        assert "submitted" not in result["result"] and delivered == []
        with pytest.raises(PageStateError):
            state.read()
        stale = await tool.execute(request)
        assert stale["error"]["code"] == "TARGET_STALE" and stale["result"]["pressed"] is False
        assert await page.evaluate("window.keys") == ["Enter"]
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("html, code", [
    ('<input style="display:none">', "ELEMENT_NOT_VISIBLE"),
    ('<div inert><input></div>', "ELEMENT_DISABLED"),
    ('<input readonly>', "BLOCKED_ACTION"),
    ('<div contenteditable role="textbox">Editor</div>', "BLOCKED_ACTION"),
])
def test_ineligible_target_receives_no_key_and_preserves_state(site, html, code):
    async def check(page):
        state, tool, request, delivered = await observed(page, html)
        before = state.read()
        result = await tool.execute(request)
        assert result["status"] == "failed" and result["error"]["code"] == code
        assert result["result"]["pressed"] is False and await page.evaluate("window.keys") == []
        assert state.read() == before and delivered == []
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("handler, code", [
    ("document.querySelector('#other').focus()", "BLOCKED_ACTION"),
    ("this.replaceWith(document.createElement('input'))", "TARGET_STALE"),
])
def test_focus_handler_cannot_redirect_enter_to_another_input(site, handler, code):
    async def check(page):
        state, tool, request, _ = await observed(page,
            f'<input onfocus="{handler}"><input id="other">')
        result = await tool.execute(request)
        assert result["error"]["code"] == code and result["result"]["pressed"] is False
        assert await page.evaluate("window.keys") == []
        with pytest.raises(PageStateError):
            state.read()
    asyncio.run(with_page(site, check))


def test_unknown_old_replaced_and_closed_targets_are_not_retried(site):
    async def check(page):
        state, tool, request, _ = await observed(page, '<input>')
        unknown = {**request, "target": {"element_id": "absent"}}
        wrong = {**request, "context": {**request["context"], "state_id": "old"}}
        assert (await tool.execute(unknown))["error"]["code"] == "ELEMENT_NOT_FOUND"
        assert (await tool.execute(wrong))["error"]["code"] == "TARGET_STALE"
        await page.evaluate("const old=document.querySelector('input'); old.replaceWith(old.cloneNode(true))")
        await wait_for_invalidation(state)
        stale = await tool.execute(request)
        assert stale["error"]["code"] == "TARGET_STALE" and stale["result"]["pressed"] is False
        assert await page.evaluate("window.keys") == []
        await page.close()
        closed = await tool.execute(request)
        assert closed["error"]["code"] == "PAGE_CLOSED" and closed["error"]["recoverable"] is False
        assert closed["result"]["pressed"] is False
    asyncio.run(with_page(site, check))


def test_timeout_before_keyboard_command_is_not_an_unknown_press(site, monkeypatch):
    async def check(page):
        state, tool, request, _ = await observed(page, '<input>', timeout_ms=50)
        before = state.read()

        async def delayed(*args, **kwargs):
            await asyncio.Future()

        monkeypatch.setattr(tool.elements, "resolve", delayed)
        result = await tool.execute(request)
        assert result["status"] == "timeout" and result["result"]["pressed"] is False
        assert state.read() == before and await page.evaluate("window.keys") == []
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("failure", ["timeout", "cancel", "browser_error"])
def test_interrupted_keyboard_completion_does_not_repeat_real_enter(site, monkeypatch, failure):
    async def check(page):
        state, tool, request, _ = await observed(page, '<input>', timeout_ms=1000)
        sent = asyncio.Event()
        original = Keyboard.press

        async def interrupted(keyboard, key, **kwargs):
            await original(keyboard, key, **kwargs)
            sent.set()
            if failure == "browser_error":
                raise Error("Interrupted browser reply")
            await asyncio.Future()

        monkeypatch.setattr(Keyboard, "press", interrupted)
        task = asyncio.create_task(tool.execute(request))
        await asyncio.wait_for(sent.wait(), 3)
        if failure == "cancel":
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            result = await task
            assert result["result"]["pressed"] is None
            assert result["status"] == ("timeout" if failure == "timeout" else "failed")
        assert await page.evaluate("window.keys") == ["Enter"]
        with pytest.raises(PageStateError):
            state.read()
        assert tool.page_events.begin("later") == []
        tool.page_events.end()
        assert (await tool.execute(request))["result"]["pressed"] is False
        assert await page.evaluate("window.keys") == ["Enter"]
    asyncio.run(with_page(site, check))


def test_popup_notification_keeps_original_page_and_does_not_switch_tools(site):
    async def check(page):
        state, tool, request, delivered = await observed(page,
            f'<input onkeydown="if(event.key===\'Enter\') window.open(\'{site}/destination\')">')
        async with page.expect_popup() as pending:
            result = await tool.execute(request)
        popup = await pending.value
        assert result["status"] == "success" and result["result"]["pressed"] is True
        assert tool.elements.page is page and state.page is page and popup is not page
        assert any(event["kind"] == "popup" and event_page is popup for event, event_page in delivered)
        assert result["result"]["event_scope"] == "press_key_call_interval"
        assert all(event["observed_during_action_id"] == request["action_id"]
                   for event in result["result"]["page_events"])
        await popup.close()
    asyncio.run(with_page(site, check))


def test_input_and_configuration_validation_before_browser_access():
    # A plain holder is enough: invalid requests must fail before touching Page.
    holder = type("Elements", (), {"state": None})()
    events = type("Events", (), {"state": None})()
    tool = PressKeyTool(holder, timeout_ms=1000, page_events=events)
    for params in ({"key": "Tab"}, {"key": "Control+Enter"}, {}, {"key": "Enter", "times": 2}):
        request = {**action("element", "state"), "params": params}
        with pytest.raises(ValidationError):
            asyncio.run(tool.execute(request))
        with pytest.raises(ValidationError):
            tool.as_port().prepare({"arguments": request}, {})
    for value in (0, -1, True, 1.5, "1000"):
        with pytest.raises(ValueError):
            PressKeyTool(holder, timeout_ms=value, page_events=events)
    with pytest.raises(ValueError):
        PressKeyTool(holder, timeout_ms=1000, page_events=type("Other", (), {"state": object()})())
