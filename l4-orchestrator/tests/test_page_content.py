from page_query_support import make_query_tool
from sdk_tool_checks import run_native_steps
"""Actual same-Page content, bounded return and existing execution connection."""
import asyncio
from copy import deepcopy
import json

import pytest
from pydantic import ValidationError

pytest.importorskip("playwright.async_api")

from l4_orchestrator.elements import ElementRegistry
from l4_orchestrator.page_events import PageEvents
from l4_orchestrator.page_state import PageState
from l4_orchestrator.ports import Authorization
from l4_orchestrator.tools.click import ClickTool
from l4_orchestrator.page_content import _COLLECT
from l4_orchestrator.tools.get_page_state import GetPageStateInput
from test_click import action as click_action
from test_interactable_elements import query as elements_query
from test_navigate import site, with_page


def query(kind="both", state_id=None):
    return {"action_id": "content-check", "tool": "get_page_state", "target": None,
            "params": {"include": ["text", "links"] if kind == "both" else [kind]},
            "context": {"job_id": "local-check", "scenario_id": "page-content",
                        "step_id": "read-content", "state_id": state_id}}


def make_tool(state, **overrides):
    limits = dict(timeout_ms=3000, max_text_bytes=10000, max_links=20, max_links_bytes=10000)
    return make_query_tool(state, **{**limits, **overrides})


def link_size(links):
    return len(json.dumps(links, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def test_main_document_text_links_and_unchanged_page(site):
    async def check(page):
        await page.goto(site)
        await page.set_content("""<!doctype html><base href="/account/">
            <p>ex<span>am</span>ple 로그인 안내</p>
            <p hidden>HIDDEN</p><p style="display:none">DISPLAY_NONE</p>
            <div style="visibility:hidden">INVISIBLE<span style="visibility:visible">Shown child</span></div>
            <a href="../login?next=%2F">로그인</a>
            <a href="#details">자세히</a><a href="mailto:help@example.test">문의</a>
            <a href="">현재 기준</a><a href="http://[">잘못된 주소</a>
            <a href="/contents" style="display:contents">A<span hidden>SECRET</span><span>B</span></a>
            <a href="/image"><img alt="Image label" width="12" height="12"></a>
            <a href="/hidden" hidden>HIDDEN_LINK</a>
            <div style="content-visibility:hidden"><a href="/hidden-layout">HIDDEN_LAYOUT</a></div>
            <input value="INPUT_VALUE"><textarea>TEXTAREA_VALUE</textarea>
            <canvas>CANVAS_FALLBACK</canvas>
            <iframe srcdoc="<p>FRAME_TEXT</p>"></iframe>
            <div id="shadow"></div>
            <p style="margin-top:2500px">Below viewport</p>""")
        await page.evaluate("""() => {
            document.querySelector('#shadow').attachShadow({mode:'open'}).innerHTML =
                '<p>SHADOW_TEXT</p><a href="/shadow">SHADOW_LINK</a>';
            window.sessionProof = 'same-document';
            document.cookie = 'content_session=kept';
        }""")
        source = await page.content()
        state = PageState(page, timeout_ms=3000)
        response = await make_tool(state).execute(query())
        assert response["status"] == "success", response
        data = response["result"]
        assert "example 로그인 안내" in data["text"]
        assert "Shown child" in data["text"] and "Below viewport" in data["text"]
        for excluded in ("HIDDEN", "DISPLAY_NONE", "INVISIBLE", "SECRET", "INPUT_VALUE",
                         "TEXTAREA_VALUE", "CANVAS_FALLBACK", "FRAME_TEXT", "SHADOW_TEXT", "SHADOW_LINK"):
            assert excluded not in data["text"]
        assert data["links"] == [
            {"text": "로그인", "href": "../login?next=%2F", "resolved_url": site + "/login?next=%2F"},
            {"text": "자세히", "href": "#details", "resolved_url": site + "/account/#details"},
            {"text": "문의", "href": "mailto:help@example.test", "resolved_url": "mailto:help@example.test"},
            {"text": "현재 기준", "href": "", "resolved_url": site + "/account/"},
            {"text": "잘못된 주소", "href": "http://[", "resolved_url": None},
            {"text": "AB", "href": "/contents", "resolved_url": site + "/contents"},
            {"text": "", "href": "/image", "resolved_url": site + "/image"},
        ]
        assert data["text_total_bytes"] == len(data["text"].encode("utf-8"))
        assert data["links_total"] == len(data["links"]) == 7
        assert data["links_bytes"] == link_size(data["links"])
        assert data["text_truncated"] is False and data["links_truncated"] is False
        assert data["page_id"] == state.page_id and data["state_id"] == response["after_state_id"]
        assert data["url"] == page.url == site + "/"
        assert data["observed_at"] and data["observation_scope"] == "main_document_light_dom"
        assert "html" not in data and response["before_state_id"] is None
        assert await page.content() == source
        assert await page.evaluate("window.sessionProof") == "same-document"
        assert "content_session=kept" in await page.evaluate("document.cookie")
        assert len(page.context.pages) == 1
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("kind", ["text", "links", "both"])
def test_requested_empty_content_is_distinct_from_unrequested(site, kind):
    async def check(page):
        await page.set_content("<body></body>")
        response = await make_tool(PageState(page, timeout_ms=3000)).execute(query(kind))
        assert response["status"] == "success", response
        data = response["result"]
        assert data["text"] == (None if kind == "links" else "")
        assert data["text_total_bytes"] == (None if kind == "links" else 0)
        assert data["text_truncated"] is (None if kind == "links" else False)
        assert data["links"] == (None if kind == "text" else [])
        assert data["links_total"] == (None if kind == "text" else 0)
        assert data["links_bytes"] == (None if kind == "text" else 2)
        assert data["links_truncated"] is (None if kind == "text" else False)
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("html", [
    '<html style="display:none"><body>Hidden<a href="/x">Link</a></body></html>',
    '<body style="display:none">Hidden<a href="/x">Link</a></body>',
    '<body style="content-visibility:hidden">Hidden<a href="/x">Link</a></body>',
])
def test_hidden_document_does_not_return_text_content_fallback(site, html):
    async def check(page):
        await page.set_content(html)
        response = await make_tool(PageState(page, timeout_ms=3000)).execute(query())
        assert response["status"] == "success", response
        assert response["result"]["text"] == "" and response["result"]["links"] == []
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("limit, expected", [(1, ""), (3, "가"), (6, "가"), (7, "가🙂"), (8, "가🙂Z")])
def test_text_limit_preserves_complete_utf8_characters(site, limit, expected):
    async def check(page):
        await page.set_content("<p>가🙂Z</p>")
        response = await make_tool(PageState(page, timeout_ms=3000), max_text_bytes=limit).execute(query("text"))
        assert response["status"] == "success", response
        data = response["result"]
        assert data["text"] == expected and len(data["text"].encode("utf-8")) <= limit
        assert data["text_total_bytes"] == 8 and data["text_truncated"] is (limit < 8)
    asyncio.run(with_page(site, check))


def test_link_count_and_json_byte_limits_are_independent_of_text(site):
    async def check(page):
        await page.goto(site)
        await page.set_content('<a href="/가?x=&quot;">한글 &quot; 인용 \\</a><a href="/two">Two</a>')
        state = PageState(page, timeout_ms=3000)
        full = (await make_tool(state).execute(query()))["result"]
        first_size = link_size(full["links"][:1])
        for overrides, expected in [
            ({"max_links": 1}, full["links"][:1]),
            ({"max_links_bytes": first_size}, full["links"][:1]),
            ({"max_links_bytes": first_size - 1}, []),
            ({"max_links_bytes": 2}, []),
            ({"max_links_bytes": link_size(full["links"])}, full["links"]),
        ]:
            response = await make_tool(state, **overrides).execute(query())
            assert response["status"] == "success", response
            data = response["result"]
            assert data["links"] == expected and data["links_total"] == 2
            assert data["links_bytes"] == link_size(expected)
            assert data["links_truncated"] is (len(expected) < 2)
            assert data["text"] == full["text"] and data["text_truncated"] is False
        text_limited = (await make_tool(state, max_text_bytes=1).execute(query()))["result"]
        assert text_limited["text_truncated"] is True and text_limited["links_truncated"] is False
    asyncio.run(with_page(site, check))


def test_click_then_content_reads_same_session_and_rejects_old_state(site):
    async def check(page):
        await page.goto(site)
        await page.set_content("""<button onclick="document.querySelector('#message').textContent='로그인 필요';
            document.querySelector('a').href='/login';window.clicks++">Continue</button>
            <p id="message">안내</p><a href="/start">Account</a>""")
        await page.evaluate("window.clicks=0; document.cookie='session=kept'")
        state = PageState(page, timeout_ms=3000)
        registry = ElementRegistry(state, timeout_ms=3000)
        elements = await make_query_tool(registry.state, elements=registry).execute(elements_query())
        snapshot = elements["result"]
        tool = make_tool(state)
        first = await tool.execute(query(state_id=snapshot["state_id"]))
        assert first["status"] == "success" and first["after_state_id"] == snapshot["state_id"]
        assert state.read()["state_id"] == snapshot["state_id"]  # Explicit ID is not refreshed.
        events = PageEvents(state, on_event=lambda event, event_page: None)
        clicked = await ClickTool(registry, timeout_ms=3000, page_events=events).execute(
            click_action(snapshot["elements"][0]["element_id"], snapshot["state_id"]))
        assert clicked["status"] == "success", clicked
        old = await tool.execute(query(state_id=snapshot["state_id"]))
        assert old["status"] == "failed" and old["error"]["code"] == "STATE_CHANGED"
        assert old["result"] is None
        current = await tool.execute(query())
        assert current["status"] == "success", current
        assert "로그인 필요" in current["result"]["text"]
        assert current["result"]["links"][0]["resolved_url"] == site + "/login"
        assert current["result"]["page_id"] == snapshot["page_id"]
        assert current["after_state_id"] != snapshot["state_id"]
        assert await page.evaluate("window.clicks") == 1
        assert "session=kept" in await page.evaluate("document.cookie")
        wrong = await tool.execute(query(state_id="another-page-state"))
        assert wrong["error"]["code"] == "STATE_CHANGED" and wrong["result"] is None
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("change, code", [("dom", "STATE_CHANGED"), ("navigate", "STATE_CHANGED"),
                                        ("close", "PAGE_CLOSED")])
def test_change_between_observation_and_read_is_not_retried(site, monkeypatch, change, code):
    async def check(page):
        await page.goto(site)
        await page.set_content("<p>Before</p>")
        state = PageState(page, timeout_ms=3000)
        tool = make_tool(state)
        original_observe = state.observe
        calls = []

        async def changed_observe(expected):
            snapshot = await original_observe(expected)
            calls.append(True)
            if change == "dom":
                await page.evaluate("document.querySelector('p').textContent='After'")
            elif change == "navigate":
                await page.goto(site + "/destination")
            else:
                await page.close()
            return snapshot

        monkeypatch.setattr(state, "observe", changed_observe)
        response = await tool.execute(query())
        assert response["status"] == "failed" and response["error"]["code"] == code
        assert response["result"] is None and response["after_state_id"] is None
        assert len(calls) == 1
        monkeypatch.setattr(state, "observe", original_observe)
        if change != "close":
            recovered = await tool.execute(query())
            assert recovered["status"] == "success", recovered
            assert recovered["result"]["text"] == ("After" if change == "dom" else "Loaded")
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("ending", ["timeout", "cancel"])
def test_unfinished_content_read_has_no_success_or_retry(site, monkeypatch, ending):
    async def check(page):
        await page.set_content("<p>Read me</p>")
        state = PageState(page, timeout_ms=3000)
        snapshot = await state.refresh()
        original_evaluate = page.evaluate
        entered, calls = asyncio.Event(), []

        async def delayed_read(expression, arg=None):
            if expression == _COLLECT:
                calls.append(True)
                entered.set()
                await asyncio.Event().wait()  # Inject an unresponsive browser transport.
            return await original_evaluate(expression, arg)

        monkeypatch.setattr(page, "evaluate", delayed_read)
        tool = make_tool(state, timeout_ms=100 if ending == "timeout" else 3000)
        pending = asyncio.create_task(tool.execute(query(state_id=snapshot["state_id"])))
        await entered.wait()
        if ending == "cancel":
            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pending
        else:
            response = await pending
            assert response["status"] == "timeout" and response["error"]["code"] == "ACTION_TIMEOUT"
            assert response["result"] is None and response["after_state_id"] is None
        assert len(calls) == 1 and not page.is_closed()
        monkeypatch.setattr(page, "evaluate", original_evaluate)
        recovered = await make_tool(state).execute(query())
        assert recovered["status"] == "success" and recovered["result"]["text"] == "Read me"
    asyncio.run(with_page(site, check))


def test_invalid_requests_and_caller_limits_are_rejected():
    for replacement in ({"params": {"include": ["html"]}}, {"params": {"kind": "both"}},
                        {"target": {"url": "https://example.test"}},
                        {"params": {"include": ["text", "links"], "save": True}}):
        with pytest.raises(ValidationError):
            GetPageStateInput.model_validate({**query(), **replacement})
    for setting, bad in (("timeout_ms", 0), ("max_text_bytes", True), ("max_links", -1),
                         ("max_links_bytes", 1)):
        with pytest.raises(ValueError):
            make_tool(None, **{setting: bad})


def test_actual_content_to_sdk_store_and_next_manager_input(site):
    async def check(page):
        await page.goto(site)
        await page.set_content('<p>계정 확인 안내</p><a href="/login">계속</a>')
        original = await page.content()
        tool = make_tool(PageState(page, timeout_ms=3000))
        proof = await run_native_steps({"get_page_state": tool}, [("get_page_state", query())])
        assert proof.results[0]["status"] == "success"
        data = proof.results[0]["result"]
        assert data["text"] == "계정 확인 안내\n\n계속"
        assert data["links"] == [{"text": "계속", "href": "/login", "resolved_url": site + "/login"}]
        assert await page.content() == original
    asyncio.run(with_page(site, check))
