from sdk_tool_checks import run_native_steps
import asyncio
from copy import deepcopy

import pytest
from pydantic import ValidationError

pytest.importorskip("playwright.async_api")
from playwright.async_api import ElementHandle, Error, JSHandle, TimeoutError as BrowserTimeoutError

from l4_orchestrator.page_events import PageEvents
from l4_orchestrator.page_state import PageStateError
from l4_orchestrator.ports import Authorization
from l4_orchestrator.tools.check import CheckInput, CheckTool
from l4_orchestrator.tools.fill import FillTool, _PRESETS
from test_fill import action as fill_action
from test_interactable_elements import query, setup
from test_navigate import site, with_page
from test_page_state import wait_for_invalidation


HTML = '<input type="checkbox" aria-label="Show details">'


def action(element_id, state_id):
    return {"action_id": "check-control", "tool": "check", "target": {"element_id": element_id},
            "params": {}, "context": {"job_id": "local-check", "scenario_id": "check",
                                       "step_id": "show-details", "state_id": state_id}}


async def observed(page, html=HTML, *, timeout_ms=3000):
    state, registry, queries = await setup(page, html)
    found = await queries.execute(query(visible_only=False))
    assert found["status"] == "success", found
    events = []
    bridge = PageEvents(state, on_event=lambda event, event_page: events.append((event, event_page)))
    return state, CheckTool(registry, timeout_ms=timeout_ms, page_events=bridge), found["result"]["elements"][0], queries, events


def test_checkbox_through_sdk_then_fresh_query_and_fill(site):
    async def check(page):
        html = '<input type="checkbox" aria-label="Show details" onchange="document.querySelector(\'#details\').hidden=false"><input id="details" aria-label="Details" hidden>'
        state, tool, target, queries, events = await observed(page, html)
        assert target["checked"] is False and target["indeterminate"] is False
        await page.evaluate("window.changes=0; document.addEventListener('change',()=>window.changes++)")
        request = action(target["element_id"], state.read()["state_id"])
        proof = await run_native_steps({"check": tool}, [("check", request)])
        result = proof.results[0]
        assert result["status"] == "success" and result["result"]["checked"] is True
        assert await page.locator('[type="checkbox"]').is_checked() and await page.evaluate("window.changes") == 1
        assert result["before_state_id"] == request["context"]["state_id"]
        assert result["after_state_id"] is None and events == []
        with pytest.raises(PageStateError):
            state.read()
        stale = await tool.execute(request)
        assert stale["error"]["code"] == "TARGET_STALE" and stale["result"]["checked"] is None
        fresh = (await queries.execute(query()))["result"]
        assert fresh["elements"][0]["checked"] is True
        field = next(item for item in fresh["elements"] if item["name"] == "Details")
        filled = await FillTool(tool.elements, timeout_ms=3000, page_events=tool.page_events).execute(
            fill_action(field["element_id"], fresh["state_id"]))
        assert filled["status"] == "success" and await page.locator('#details').input_value() == _PRESETS["dummy_text"]
    asyncio.run(with_page(site, check))


def test_radio_selects_target_and_clears_other_group_member(site):
    async def check(page):
        html = '<input type="radio" name="mode" aria-label="Detailed"><input type="radio" name="mode" aria-label="Basic" checked>'
        state, tool, target, queries, events = await observed(page, html)
        assert target["checked"] is False and "indeterminate" not in target
        result = await tool.execute(action(target["element_id"], state.read()["state_id"]))
        assert result["status"] == "success" and result["result"]["checked"] is True
        assert await page.locator('input').evaluate_all("nodes=>nodes.map(n=>n.checked)") == [True, False]
        fresh = (await queries.execute(query()))["result"]
        assert [item["checked"] for item in fresh["elements"]] == [True, False]
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("kind", ["checkbox", "radio"])
def test_already_checked_succeeds_without_input_or_invalidating_state(site, monkeypatch, kind):
    async def check(page):
        state, tool, target, queries, events = await observed(page, f'<input type="{kind}" checked>')
        before = state.read()
        await page.evaluate("window.inputs=0; window.changes=0; window.clicks=0; document.addEventListener('input',()=>window.inputs++); document.addEventListener('change',()=>window.changes++); document.addEventListener('click',()=>window.clicks++)")

        async def unexpected_check(node, **kwargs):
            pytest.fail("Already checked must not call Playwright check")

        monkeypatch.setattr(ElementHandle, "check", unexpected_check)
        result = await tool.execute(action(target["element_id"], None))
        assert result["status"] == "success" and result["result"]["checked"] is True
        assert result["before_state_id"] == result["after_state_id"] == before["state_id"]
        assert state.read() == before and events == [] and tool.page_events._events is None
        assert await page.evaluate("[window.inputs,window.changes,window.clicks]") == [0, 0, 0]
    asyncio.run(with_page(site, check))


def test_observation_reads_runtime_properties_without_leaking_values(site):
    async def check(page):
        html = '<input type="checkbox" checked value="private"><input type="radio"><input value="secret"><div role="checkbox" aria-checked="true">Custom</div>'
        state, tool, target, queries, events = await observed(page, html)
        await page.evaluate("const n=document.querySelector('input'); n.checked=false; n.indeterminate=true; document.querySelector('[type=radio]').checked=true")
        result = await queries.execute(query())
        items = result["result"]["elements"]
        assert items[0]["checked"] is False and items[0]["indeterminate"] is True
        assert items[1]["checked"] is True and "indeterminate" not in items[1]
        assert all("checked" not in item and "indeterminate" not in item for item in items[2:])
        assert "private" not in str(result) and "secret" not in str(result)
    asyncio.run(with_page(site, check))


def test_params_accept_no_uncheck_or_extra_arguments():
    valid = action("el", "state")
    assert CheckInput.model_validate(valid).params.model_dump() == {}
    for params in ({"checked": False}, {"force": True}, {"value": True}, None, []):
        invalid = deepcopy(valid)
        invalid["params"] = params
        with pytest.raises(ValidationError):
            CheckInput.model_validate(invalid)


@pytest.mark.parametrize("html,code", [
    ('<input type="checkbox" disabled>', "ELEMENT_DISABLED"),
    ('<input type="checkbox" checked disabled>', "ELEMENT_DISABLED"),
    ('<fieldset disabled><input type="radio"></fieldset>', "ELEMENT_DISABLED"),
    ('<div aria-disabled="TrUe"><input type="checkbox"></div>', "ELEMENT_DISABLED"),
    ('<input type="checkbox" inert>', "ELEMENT_DISABLED"),
    ('<input type="checkbox" style="display:none">', "ELEMENT_NOT_VISIBLE"),
    ('<input type="radio" checked style="visibility:hidden">', "ELEMENT_NOT_VISIBLE"),
    ('<input aria-label="Text">', "BLOCKED_ACTION"),
    ('<div role="checkbox" aria-checked="false">Custom</div>', "BLOCKED_ACTION"),
])
def test_preflight_rejection_does_not_click_or_claim_unchecked(site, monkeypatch, html, code):
    async def check(page):
        state, tool, target, queries, events = await observed(page, html)
        before = state.read()

        async def unexpected_check(node, **kwargs):
            pytest.fail("Rejected target must not reach Playwright check")

        monkeypatch.setattr(ElementHandle, "check", unexpected_check)
        result = await tool.execute(action(target["element_id"], before["state_id"]))
        assert result["status"] == "failed" and result["error"]["code"] == code, result
        assert result["result"]["checked"] is None and state.read() == before and events == []
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("initial", [False, True])
def test_indeterminate_is_observed_and_rejected_without_input(site, initial):
    async def check(page):
        state, tool, target, queries, events = await observed(page)
        await page.locator("input").evaluate("(n,checked)=>{n.checked=checked; n.indeterminate=true}", initial)
        fresh = (await queries.execute(query()))["result"]
        assert fresh["elements"][0]["indeterminate"] is True
        result = await tool.execute(action(target["element_id"], fresh["state_id"]))
        assert result["error"]["code"] == "BLOCKED_ACTION" and result["result"]["checked"] is None
        assert await page.locator("input").evaluate("n=>[n.checked,n.indeterminate]") == [initial, True]
        assert state.read()["state_id"] == fresh["state_id"]
    asyncio.run(with_page(site, check))


def test_explicit_aria_enabled_override_and_runtime_checked_drift(site):
    async def check(page):
        html = '<div aria-disabled="true"><input type="checkbox" aria-disabled="FALSE" checked></div>'
        state, tool, target, queries, events = await observed(page, html)
        assert target["enabled"] is True and target["checked"] is True
        # Property-only change is not a DOM attribute mutation; action must inspect it live.
        await page.locator("input").evaluate("n=>{n.checked=false}")
        result = await tool.execute(action(target["element_id"], state.read()["state_id"]))
        assert result["status"] == "success" and result["after_state_id"] is None
        assert await page.locator("input").is_checked()
    asyncio.run(with_page(site, check))


def test_unknown_foreign_state_and_replaced_node_are_not_retargeted(site):
    async def check(page):
        state, tool, target, queries, events = await observed(page)
        for element_id, state_id, code in (("unknown", state.read()["state_id"], "ELEMENT_NOT_FOUND"),
                                          (target["element_id"], "foreign-state", "TARGET_STALE")):
            result = await tool.execute(action(element_id, state_id))
            assert result["error"]["code"] == code and result["result"]["checked"] is None
        old_id = state.read()["state_id"]
        await page.evaluate("const n=document.querySelector('input'); n.replaceWith(n.cloneNode(true))")
        await wait_for_invalidation(state)
        result = await tool.execute(action(target["element_id"], old_id))
        assert result["error"]["code"] == "TARGET_STALE" and not await page.locator("input").is_checked()
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("handler,code", [
    ("this.checked=false", "BLOCKED_ACTION"),
    ("this.replaceWith(this.cloneNode(true))", "TARGET_STALE"),
    ("this.type='radio'", "BLOCKED_ACTION"),
    ("this.indeterminate=true", "BLOCKED_ACTION"),
])
def test_site_reversal_replacement_type_change_or_mixed_state_cannot_claim_success(site, handler, code):
    async def check(page):
        html = '<input type="checkbox" onchange="window.changes++; ' + handler + '">'
        state, tool, target, queries, events = await observed(page, html)
        await page.evaluate("window.changes=0")
        result = await tool.execute(action(target["element_id"], state.read()["state_id"]))
        assert result["status"] == "failed" and result["error"]["code"] == code, result
        assert result["result"]["checked"] is None and await page.evaluate("window.changes") == 1
        assert result["after_state_id"] is None and tool.page_events._events is None
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("error_class", [Error, BrowserTimeoutError])
def test_error_after_actual_check_does_not_claim_nothing_happened(site, monkeypatch, error_class):
    async def check(page):
        state, tool, target, queries, events = await observed(page)
        original, calls = ElementHandle.check, []

        async def check_then_error(node, **kwargs):
            calls.append(True)
            await original(node, **kwargs)
            raise error_class("Response lost")

        monkeypatch.setattr(ElementHandle, "check", check_then_error)
        result = await tool.execute(action(target["element_id"], state.read()["state_id"]))
        assert result["status"] == ("timeout" if error_class is BrowserTimeoutError else "failed")
        assert result["result"]["checked"] is None and result["after_state_id"] is None
        assert await page.locator("input").is_checked() and len(calls) == 1
    asyncio.run(with_page(site, check))


def test_covered_control_times_out_without_force(site):
    async def check(page):
        html = HTML + '<div style="position:fixed;inset:0;z-index:1000;background:white"></div>'
        state, tool, target, queries, events = await observed(page, html, timeout_ms=350)
        result = await tool.execute(action(target["element_id"], state.read()["state_id"]))
        assert result["status"] == "timeout" and result["result"]["checked"] is None
        assert not await page.locator("input").is_checked() and tool.page_events._events is None
        with pytest.raises(PageStateError):
            state.read()
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("terminal", ["closed", "crash"])
def test_terminal_error_overrides_timeout(site, monkeypatch, terminal):
    async def check(page):
        state, tool, target, queries, events = await observed(page)
        request = action(target["element_id"], state.read()["state_id"])

        async def terminate(node, **kwargs):
            if terminal == "closed":
                await page.close()
            else:
                state._on_crash(page)  # Notification injection, not a real browser crash.
            raise BrowserTimeoutError("Interrupted")

        monkeypatch.setattr(ElementHandle, "check", terminate)
        for result in (await tool.execute(request), await tool.execute(request)):
            assert result["status"] == "failed" and result["error"]["recoverable"] is False
            assert result["error"]["code"] == ("PAGE_CLOSED" if terminal == "closed" else "BROWSER_CRASH")
            assert result["result"]["checked"] is None
    asyncio.run(with_page(site, check))


def test_cancellation_releases_node_and_action_interval(site, monkeypatch):
    async def check(page):
        state, tool, target, queries, events = await observed(page)
        started, calls, disposed = asyncio.Event(), [], []
        original_dispose = JSHandle.dispose

        async def dispose(handle):
            disposed.append(handle)
            await original_dispose(handle)

        async def pending_check(node, **kwargs):
            calls.append(True)
            started.set()
            await asyncio.Event().wait()

        monkeypatch.setattr(ElementHandle, "check", pending_check)
        monkeypatch.setattr(JSHandle, "dispose", dispose)
        pending = asyncio.create_task(tool.execute(action(target["element_id"], state.read()["state_id"])))
        await started.wait()
        disposed.clear()  # Resolver temporaries were already released.
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
        assert len(disposed) == 1 and len(calls) == 1 and tool.page_events._events is None
        assert not await page.locator("input").is_checked()
        with pytest.raises(PageStateError):
            state.read()
        assert (await queries.execute(query()))["status"] == "success"
    asyncio.run(with_page(site, check))


def test_navigation_event_stays_on_same_assigned_page(site, monkeypatch):
    async def check(page):
        await page.goto(site)
        html = '<input type="checkbox" onchange="history.pushState({},\'\',\'?details=1\')" >'
        state, tool, target, queries, events = await observed(page, html)
        original = ElementHandle.check

        async def check_with_notification(node, **kwargs):
            async with page.expect_event("framenavigated"):
                return await original(node, **kwargs)

        monkeypatch.setattr(ElementHandle, "check", check_with_notification)
        result = await tool.execute(action(target["element_id"], state.read()["state_id"]))
        assert result["status"] == "success" and result["result"]["checked"] is True, result
        assert len(events) == 1 and events[0][1] is page
        assert result["result"]["page_events"][0]["url"].endswith("?details=1")
        assert tool.page_events._events is None
    asyncio.run(with_page(site, check))
