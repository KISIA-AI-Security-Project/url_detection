from sdk_tool_checks import run_native_steps
import asyncio
from copy import deepcopy

import pytest
from pydantic import ValidationError

pytest.importorskip("playwright.async_api", reason="Install the browser extra to run browser tests")

from l4_orchestrator.page_events import PageEvents
from l4_orchestrator.page_state import PageStateError
from l4_orchestrator.ports import Authorization
from l4_orchestrator.tools.click import ClickTool
from test_interactable_elements import query, setup
from test_navigate import site, with_page
from test_page_state import wait_for_invalidation


def action(element_id, state_id):
    return {"action_id": "click-check", "tool": "click", "target": {"element_id": element_id},
            "params": {}, "context": {"job_id": "local-check", "scenario_id": "click",
                                      "step_id": "press", "state_id": state_id}}


async def observed(page, html, *, timeout_ms=3000, callback=None):
    state, registry, query_tool = await setup(page, html)
    result = await query_tool.execute(query(visible_only=False))
    assert result["status"] == "success", result
    element_id = result["result"]["elements"][0]["element_id"]
    request = action(element_id, state.read()["state_id"])
    events = []
    page_events = PageEvents(state, on_event=callback or (
        lambda event, event_page: events.append((event, event_page))))
    tool = ClickTool(registry, timeout_ms=timeout_ms, page_events=page_events)
    return state, tool, request, events


BUTTON = '<button onclick="window.clickCount = (window.clickCount || 0) + 1">Continue</button>'


def test_button_once_invalidates_even_without_dom_change(site):
    async def check(page):
        state, tool, request, events = await observed(page, BUTTON)
        source = await page.content()
        result = await tool.execute(request)
        assert result["status"] == "success" and result["error"] is None
        assert result["result"]["clicked"] is True
        assert await page.evaluate("window.clickCount") == 1
        assert await page.content() == source  # A DOM mutation watcher alone cannot detect this action.
        assert result["before_state_id"] == request["context"]["state_id"]
        assert result["after_state_id"] is None and result["observer_refs"] == {"l2": [], "l3": []}
        assert result["result"]["page_events"] == events == []
        with pytest.raises(PageStateError):
            state.read()
        repeated = await tool.execute(request)
        assert repeated["error"]["code"] == "TARGET_STALE"
        assert repeated["result"]["clicked"] is False
        assert await page.evaluate("window.clickCount") == 1
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("html, code", [
    ('<button style="display:none">Hidden</button>', "ELEMENT_NOT_VISIBLE"),
    ('<button disabled>Disabled</button>', "ELEMENT_DISABLED"),
    ('<div aria-disabled="TrUe"><button>Disabled by parent</button></div>', "ELEMENT_DISABLED"),
    ('<div inert><button>Inert</button></div>', "ELEMENT_DISABLED"),
])
def test_non_actionable_preconditions_do_not_attempt_click(site, html, code):
    async def check(page):
        state, tool, request, events = await observed(page, html)
        await page.evaluate("window.clickCount = 0; document.addEventListener('click', () => window.clickCount++)")
        before = state.read()
        result = await tool.execute(request)
        assert result["status"] == "failed" and result["error"]["code"] == code
        assert result["result"]["clicked"] is False and await page.evaluate("window.clickCount") == 0
        assert state.read() == before and events == []
    asyncio.run(with_page(site, check))


def test_unknown_wrong_state_and_replaced_node_cannot_click_replacement(site):
    async def check(page):
        state, tool, request, events = await observed(page, BUTTON)
        unknown = deepcopy(request)
        unknown["target"]["element_id"] = "not-published"
        result = await tool.execute(unknown)
        assert result["error"]["code"] == "ELEMENT_NOT_FOUND" and result["result"]["clicked"] is False
        wrong_state = deepcopy(request)
        wrong_state["context"]["state_id"] = "another-state"
        result = await tool.execute(wrong_state)
        assert result["error"]["code"] == "TARGET_STALE" and result["result"]["clicked"] is False
        await page.evaluate("const old = document.querySelector('button'); old.replaceWith(old.cloneNode(true))")
        await wait_for_invalidation(state)
        result = await tool.execute(request)
        assert result["error"]["code"] == "TARGET_STALE" and result["result"]["clicked"] is False
        assert await page.evaluate("window.clickCount || 0") == 0 and events == []
    asyncio.run(with_page(site, check))


def test_overlay_times_out_without_force_or_automatic_second_click(site):
    async def check(page):
        state, tool, request, events = await observed(
            page, BUTTON + '<div style="position:fixed;inset:0;z-index:99"></div>', timeout_ms=400)
        result = await tool.execute(request)
        assert result["status"] == "timeout" and result["error"]["code"] == "ACTION_TIMEOUT"
        assert result["result"]["clicked"] is None  # Attempted; Tool cannot promise no input occurred.
        assert await page.evaluate("window.clickCount || 0") == 0
        with pytest.raises(PageStateError):
            state.read()
        await page.locator("div").evaluate("node => node.remove()")
        await page.wait_for_timeout(150)
        assert await page.evaluate("window.clickCount || 0") == 0 and events == []
    asyncio.run(with_page(site, check))


def test_detached_during_actionability_wait_does_not_resolve_same_selector_again(site):
    async def check(page):
        state, tool, request, events = await observed(
            page, BUTTON + '<div style="position:fixed;inset:0;z-index:99"></div>')
        # Replace after the click attempt has started waiting for the overlay, not before resolve.
        original_invalidate = state.invalidate

        def invalidate_and_schedule():
            state.invalidate = original_invalidate
            original_invalidate()
            asyncio.create_task(page.evaluate("""() => setTimeout(() => {
                const old = document.querySelector('button'); old.replaceWith(old.cloneNode(true));
                document.querySelector('div').remove();
            }, 150)"""))

        state.invalidate = invalidate_and_schedule
        try:
            result = await tool.execute(request)
        finally:
            state.invalidate = original_invalidate
        assert result["status"] == "failed" and result["error"]["code"] == "TARGET_STALE"
        assert result["result"]["clicked"] is None
        assert await page.evaluate("window.clickCount || 0") == 0 and events == []
    asyncio.run(with_page(site, check))


def test_timeout_after_input_does_not_claim_click_was_prevented(site):
    async def check(page):
        navigations = []
        inputs = []
        await page.expose_function("reportClick", lambda: inputs.append("click"))
        page.on("request", lambda request: navigations.append(request.url) if request.is_navigation_request() else None)
        state, tool, request, events = await observed(
            page, f'<a href="{site}/slow" onclick="window.reportClick()">Slow link</a>',
            timeout_ms=400)
        result = await tool.execute(request)
        assert result["status"] == "timeout" and result["error"]["code"] == "ACTION_TIMEOUT"
        assert result["result"]["clicked"] is None
        assert inputs == ["click"]  # This evidence survives destruction of the original document.
        assert navigations.count(site + "/slow") == 1
        with pytest.raises(PageStateError):
            state.read()
        await page.wait_for_url(site + "/slow")
        assert navigations.count(site + "/slow") == 1
        # A navigation that completes after the Tool returns belongs to the caller's Page lifetime.
        assert len(events) == 1 and result["result"]["page_events"] == []
        assert events[0][0]["observed_during_action_id"] is None
    asyncio.run(with_page(site, check))


def test_navigation_notification_and_listener_cleanup(site):
    async def check(page):
        state, tool, request, events = await observed(page, f'<a href="{site}/destination">Link</a>')
        result = await tool.execute(request)
        assert result["status"] == "success" and result["result"]["clicked"] is True
        assert page.url == site + "/destination" and len(events) == 1
        event, event_page = events[0]
        assert event_page is page and event["kind"] == "navigation"
        assert event["source_page_id"] == state.page_id and event["url"] == page.url
        assert event["observed_during_action_id"] == request["action_id"]
        assert event["delivery_error"] is None and result["result"]["page_events"] == [event]
        await page.goto(site + "/other")
        assert len(events) == 2 and events[1][0]["observed_during_action_id"] is None
        tool.page_events.close()
        await page.goto(site + "/after-close")
        assert len(events) == 2  # The caller explicitly ends the Page's notification connection.
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("path", ["/destination", "/slow"])
def test_popup_is_handed_to_caller_without_switching_original_page(site, path):
    async def check(page):
        state, tool, request, events = await observed(page, f'<a href="{site}{path}" target="_blank">Popup</a>')
        before_url = page.url
        async with page.expect_popup() as popup_info:
            result = await tool.execute(request)
        popup = await popup_info.value
        assert result["status"] == "success" and result["result"]["clicked"] is True
        assert len(events) == 1, result
        event, event_page = events[0]
        assert event["kind"] == "popup" and event_page is popup
        assert event["source_page_id"] == state.page_id and event["delivery_error"] is None
        # Only events observed while clicking belong in its result. The persistent connection
        # also delivers the popup when its initial response arrives after that interval.
        assert result["result"]["page_events"] == (
            [event] if event["observed_during_action_id"] == request["action_id"] else [])
        if path == "/slow":
            assert event["observed_during_action_id"] is None
            assert result["result"]["page_events"] == []
        assert tool.elements.page is page and page.url == before_url and not popup.is_closed()
        await popup.close()  # The caller, not ClickTool, owns it.
    asyncio.run(with_page(site, check))


def test_callback_failure_preserves_click_outcome(site):
    async def check(page):
        calls = []

        def broken_callback(event, event_page):
            calls.append((event, event_page))
            raise RuntimeError("Caller could not enqueue notification")

        state, tool, request, events = await observed(
            page, f'<a href="{site}/destination">Link</a>', callback=broken_callback)
        result = await tool.execute(request)
        assert result["status"] == "success" and result["error"] is None
        assert result["result"]["clicked"] is True and len(calls) == 1
        assert result["result"]["page_events"][0]["delivery_error"] == "PAGE_EVENT_DELIVERY_FAILED"
        assert tool.page_events.last_delivery_error == result["result"]["page_events"][0]
        assert page.url == site + "/destination"
    asyncio.run(with_page(site, check))


def test_invalid_extra_and_closed_page_do_not_attempt_click(site):
    async def check(page):
        state, tool, request, events = await observed(page, BUTTON)
        extra = deepcopy(request)
        extra["params"]["force"] = True
        with pytest.raises(ValidationError):
            await tool.execute(extra)
        assert await page.evaluate("window.clickCount || 0") == 0
        await page.close()
        result = await tool.execute(request)
        assert result["status"] == "failed" and result["error"]["code"] == "PAGE_CLOSED"
        assert result["result"]["clicked"] is False and events == []
    asyncio.run(with_page(site, check))


def test_sdk_receives_one_click_result(site):
    async def check(page):
        page_state, tool, request, events = await observed(page, BUTTON)
        proof = await run_native_steps({"click": tool}, [("click", request)])
        assert proof.results[0]["result"]["clicked"] is True
        assert await page.evaluate("window.clickCount") == 1 and len(proof.actions) == 1
    asyncio.run(with_page(site, check))
