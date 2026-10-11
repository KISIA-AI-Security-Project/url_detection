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
from l4_orchestrator.tools.fill import FillTool, _PRESETS
from l4_orchestrator.tools.select_option import SelectOptionInput, SelectOptionTool
from test_fill import action as fill_action
from test_interactable_elements import query, setup
from test_navigate import site, with_page
from test_page_state import wait_for_invalidation


OPTIONS = '<option value="">Choose</option><option value="KR" label="Korea">Korean text</option><option value="US">United States</option>'
HTML = '<select aria-label="Country">' + OPTIONS + '</select>'


def action(element_id, state_id, **params):
    return {"action_id": "select-check", "tool": "select_option", "target": {"element_id": element_id},
            "params": params, "context": {"job_id": "local-check", "scenario_id": "select",
                                         "step_id": "choose", "state_id": state_id}}


async def observed(page, html=HTML, *, timeout_ms=3000):
    state, registry, query_tool = await setup(page, html)
    found = await query_tool.execute(query(visible_only=False))
    assert found["status"] == "success", found
    target = found["result"]["elements"][0]
    events = []
    bridge = PageEvents(state, on_event=lambda event, event_page: events.append((event, event_page)))
    return state, SelectOptionTool(registry, timeout_ms=timeout_ms, page_events=bridge), target, query_tool, events


@pytest.mark.parametrize("params", [{"value": "KR"}, {"label": "Korea"}, {"index": 1}])
def test_observed_options_select_exact_value_label_or_index_once(site, params):
    async def check(page):
        state, tool, target, queries, events = await observed(page, HTML + '<input value="private-input">')
        assert target["multiple"] is False
        assert target["options"] == [
            {"index": 0, "value": "", "label": "Choose", "enabled": True, "selected": True},
            {"index": 1, "value": "KR", "label": "Korea", "enabled": True, "selected": False},
            {"index": 2, "value": "US", "label": "United States", "enabled": True, "selected": False}]
        await page.evaluate("window.changes=0; window.inputs=0; document.querySelector('select').addEventListener('change',()=>window.changes++); document.querySelector('select').addEventListener('input',()=>window.inputs++)")
        request = action(target["element_id"], state.read()["state_id"], **params)
        result = await tool.execute(request)
        assert result["status"] == "success" and result["result"]["selected"] is True
        assert result["result"]["selected_value"] == "KR" and await page.locator("select").input_value() == "KR"
        assert await page.evaluate("[window.inputs,window.changes]") == [1, 1]
        assert result["before_state_id"] == request["context"]["state_id"] and result["after_state_id"] is None
        with pytest.raises(PageStateError):
            state.read()
        stale = await tool.execute(request)
        assert stale["error"]["code"] == "TARGET_STALE" and stale["result"]["selected"] is False
        fresh = await queries.execute(query())
        assert fresh["result"]["elements"][0]["options"][1]["selected"] is True
        assert "options" not in fresh["result"]["elements"][1] and "private-input" not in str(fresh)
        assert await page.evaluate("window.changes") == 1 and events == []
    asyncio.run(with_page(site, check))


def test_empty_value_and_already_selected_option_are_valid(site):
    async def check(page):
        state, tool, target, queries, events = await observed(page)
        await page.evaluate("window.changes=0; document.querySelector('select').addEventListener('change',()=>window.changes++)")
        result = await tool.execute(action(target["element_id"], state.read()["state_id"], value=""))
        assert result["status"] == "success" and result["result"]["selected_value"] == ""
        assert result["result"]["selected"] is True and await page.evaluate("window.changes") == 1
    asyncio.run(with_page(site, check))


def test_exactly_one_strict_selector_is_required():
    for params in ({}, {"value": "KR", "label": "Korea"}, {"value": "KR", "index": 1},
                   {"label": "Korea", "index": 1}, {"value": ["KR"]}, {"index": -1},
                   {"index": True}, {"index": "1"}, {"index": 1.5}, {"value": None},
                   {"value": 1}, {"label": False}, {"value": "KR", "force": True}):
        with pytest.raises(ValidationError):
            SelectOptionInput.model_validate(action("el", "state", **params))


@pytest.mark.parametrize("html, params, code", [
    ('<select disabled>' + OPTIONS + '</select>', {"value": "KR"}, "ELEMENT_DISABLED"),
    ('<fieldset disabled><select>' + OPTIONS + '</select></fieldset>', {"value": "KR"}, "ELEMENT_DISABLED"),
    ('<div aria-disabled="TrUe"><select>' + OPTIONS + '</select></div>', {"value": "KR"}, "ELEMENT_DISABLED"),
    ('<select inert>' + OPTIONS + '</select>', {"value": "KR"}, "ELEMENT_DISABLED"),
    ('<select style="display:none">' + OPTIONS + '</select>', {"value": "KR"}, "ELEMENT_NOT_VISIBLE"),
    ('<select multiple>' + OPTIONS + '</select>', {"value": "KR"}, "BLOCKED_ACTION"),
    ('<div role="combobox" tabindex="0">Korea</div>', {"value": "KR"}, "BLOCKED_ACTION"),
    ('<select><option>A</option><option disabled value="KR">Korea</option></select>', {"value": "KR"}, "ELEMENT_DISABLED"),
    ('<select><option>A</option><optgroup disabled><option value="KR">Korea</option></optgroup></select>', {"value": "KR"}, "ELEMENT_DISABLED"),
    ('<select><option>A</option><option aria-disabled="TrUe" value="KR">Korea</option></select>', {"value": "KR"}, "ELEMENT_DISABLED"),
    ('<select><option>A</option><optgroup aria-disabled="true"><option value="KR">Korea</option></optgroup></select>', {"value": "KR"}, "ELEMENT_DISABLED"),
    (HTML, {"value": "missing"}, "ELEMENT_NOT_FOUND"),
    (HTML, {"label": "Korean text"}, "ELEMENT_NOT_FOUND"),
    (HTML, {"index": 99}, "ELEMENT_NOT_FOUND"),
    ('<select><option>A</option><option value="KR">One</option><option value="KR">Two</option></select>', {"value": "KR"}, "BLOCKED_ACTION"),
    ('<select><option>A</option><option value="1">Same</option><option value="2">Same</option></select>', {"label": "Same"}, "BLOCKED_ACTION"),
])
def test_preconditions_reject_without_changing_selection(site, html, params, code):
    async def check(page):
        state, tool, target, queries, events = await observed(page, html)
        before = state.read()
        await page.evaluate("window.changes=0; document.addEventListener('change',()=>window.changes++)")
        result = await tool.execute(action(target["element_id"], before["state_id"], **params))
        assert result["status"] == "failed" and result["error"]["code"] == code, result
        assert result["result"]["selected"] is False and result["result"]["selected_value"] is None
        assert state.read() == before and await page.evaluate("window.changes") == 0 and events == []
        if code == "ELEMENT_DISABLED" and "options" in target:
            assert target["options"][1]["enabled"] is False
    asyncio.run(with_page(site, check))


def test_option_explicit_aria_enabled_overrides_group_aria_disabled(site):
    async def check(page):
        html = '<select><option>A</option><optgroup aria-disabled="true"><option aria-disabled="FALSE" value="KR">Korea</option></optgroup></select>'
        state, tool, target, queries, events = await observed(page, html)
        assert target["options"][1]["enabled"] is True
        result = await tool.execute(action(target["element_id"], state.read()["state_id"], value="KR"))
        assert result["status"] == "success" and result["result"]["selected_value"] == "KR"
    asyncio.run(with_page(site, check))


def test_index_disambiguates_duplicates_and_old_or_other_page_ids_cannot_select(site):
    async def check(page):
        html = '<select><option>A</option><option value="X">Same</option><option value="X">Same</option></select>'
        state, tool, target, queries, events = await observed(page, html)
        other = await page.context.new_page()
        other_state, _, _, _, _ = await observed(other, html)
        for element_id, state_id, code in (("unknown", state.read()["state_id"], "ELEMENT_NOT_FOUND"),
                                          (target["element_id"], other_state.read()["state_id"], "TARGET_STALE")):
            result = await tool.execute(action(element_id, state_id, index=2))
            assert result["error"]["code"] == code and result["result"]["selected"] is False
        request = action(target["element_id"], state.read()["state_id"], index=2)
        result = await tool.execute(request)
        assert result["status"] == "success" and await page.locator("select").evaluate("node=>node.selectedIndex") == 2
        current = (await queries.execute(query()))["result"]
        await page.evaluate("const old=document.querySelector('select'); old.replaceWith(old.cloneNode(true))")
        await wait_for_invalidation(state)
        result = await tool.execute(action(target["element_id"], current["state_id"], index=1))
        assert result["error"]["code"] == "TARGET_STALE" and result["result"]["selected"] is False
    asyncio.run(with_page(site, check))


def test_option_replaced_during_operation_does_not_select_same_value_replacement(site, monkeypatch):
    async def check(page):
        state, tool, target, queries, events = await observed(page)
        original = ElementHandle.select_option

        async def replace_then_select(node, **kwargs):
            await page.evaluate("const old=document.querySelectorAll('option')[1]; old.replaceWith(old.cloneNode(true))")
            kwargs["timeout"] = 80
            return await original(node, **kwargs)

        monkeypatch.setattr(ElementHandle, "select_option", replace_then_select)
        result = await tool.execute(action(target["element_id"], state.read()["state_id"], value="KR"))
        assert result["status"] == "timeout" and result["result"]["selected"] is None
        assert result["result"]["selected_value"] is None and await page.locator("select").input_value() == ""
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("handler, code", [("this.value=''", "BLOCKED_ACTION"),
                                          ("this.replaceWith(this.cloneNode(true))", "TARGET_STALE")])
def test_change_handler_can_prevent_confirmation_without_automatic_retry(site, handler, code):
    async def check(page):
        html = '<select onchange="window.changes++; ' + handler + '">' + OPTIONS + '</select>'
        state, tool, target, queries, events = await observed(page, html)
        await page.evaluate("window.changes=0")
        result = await tool.execute(action(target["element_id"], state.read()["state_id"], value="KR"))
        assert result["status"] == "failed" and result["error"]["code"] == code
        assert result["result"]["selected"] is None and result["result"]["selected_value"] is None
        assert await page.evaluate("window.changes") == 1
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("error_class", [Error, BrowserTimeoutError])
def test_error_after_actual_selection_does_not_claim_it_was_prevented(site, monkeypatch, error_class):
    async def check(page):
        state, tool, target, queries, events = await observed(page)
        original, calls = ElementHandle.select_option, []

        async def select_then_error(node, **kwargs):
            calls.append(True)
            await original(node, **kwargs)
            raise error_class("Response lost after selection")

        monkeypatch.setattr(ElementHandle, "select_option", select_then_error)
        result = await tool.execute(action(target["element_id"], state.read()["state_id"], value="KR"))
        assert result["status"] == ("timeout" if error_class is BrowserTimeoutError else "failed")
        assert result["result"]["selected"] is None and result["result"]["selected_value"] is None
        assert await page.locator("select").input_value() == "KR" and len(calls) == 1
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("terminal", ["closed", "crash"])
def test_terminal_state_is_not_reported_as_recoverable_timeout(site, monkeypatch, terminal):
    async def check(page):
        state, tool, target, queries, events = await observed(page)
        request = action(target["element_id"], state.read()["state_id"], value="KR")

        async def terminate(node, **kwargs):
            if terminal == "closed":
                await page.close()
            else:
                state._on_crash(page)  # Simulated notification, not a real browser crash.
            raise BrowserTimeoutError("Protocol wait interrupted")

        monkeypatch.setattr(ElementHandle, "select_option", terminate)
        code = "PAGE_CLOSED" if terminal == "closed" else "BROWSER_CRASH"
        first, second = await tool.execute(request), await tool.execute(request)
        assert first["result"]["selected"] is None and second["result"]["selected"] is False
        for result in (first, second):
            assert result["status"] == "failed" and result["error"]["code"] == code
            assert result["error"]["recoverable"] is False
    asyncio.run(with_page(site, check))


def test_cancellation_propagates_and_releases_handles_and_action_interval(site, monkeypatch):
    async def check(page):
        state, tool, target, queries, events = await observed(page)
        started, calls = asyncio.Event(), []
        disposed, original_dispose = [], JSHandle.dispose

        async def dispose(handle):
            disposed.append(handle)
            await original_dispose(handle)

        async def pending_select(node, **kwargs):
            calls.append(True)
            started.set()
            await asyncio.Event().wait()

        monkeypatch.setattr(ElementHandle, "select_option", pending_select)
        monkeypatch.setattr(JSHandle, "dispose", dispose)
        pending = asyncio.create_task(tool.execute(action(target["element_id"], state.read()["state_id"], value="KR")))
        await started.wait()
        disposed.clear()  # Count the three action-owned handles, after resolver cleanup.
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
        assert tool.page_events._events is None and len(calls) == 1
        assert len(disposed) == 3 and len({id(handle) for handle in disposed}) == 3
        assert await page.locator("select").input_value() == ""
        with pytest.raises(PageStateError):
            state.read()
        assert (await queries.execute(query()))["status"] == "success"
    asyncio.run(with_page(site, check))


def test_navigation_notifications_keep_the_same_page_and_selection_result(site, monkeypatch):
    async def check(page):
        await page.goto(site)
        html = '<select onchange="history.pushState({},\'\',\'?country=\'+this.value)">' + OPTIONS + '</select>'
        state, tool, target, queries, events = await observed(page, html)
        original = ElementHandle.select_option

        async def select_and_wait_for_notification(node, **kwargs):
            async with page.expect_event("framenavigated"):
                return await original(node, **kwargs)

        monkeypatch.setattr(ElementHandle, "select_option", select_and_wait_for_notification)
        result = await tool.execute(action(target["element_id"], state.read()["state_id"], value="KR"))
        assert result["status"] == "success" and result["result"]["selected_value"] == "KR"
        assert len(events) == 1 and events[0][1] is page
        assert result["result"]["page_events"][0]["url"].endswith("?country=KR")
        assert tool.page_events._events is None
    asyncio.run(with_page(site, check))


def test_actual_select_through_sdk_then_fresh_query_and_fill(site):
    async def check(page):
        html = '<select onchange="document.querySelector(\'input\').hidden=false">' + OPTIONS + '</select><input aria-label="Region" hidden>'
        state, tool, target, queries, events = await observed(page, html)
        request = action(target["element_id"], state.read()["state_id"], label=target["options"][1]["label"])
        proof = await run_native_steps({"select_option": tool}, [("select_option", request)])
        result = proof.results[0]
        assert result["result"]["selected_value"] == "KR" and result["result"]["selected"] is True
        fresh = (await queries.execute(query()))["result"]
        field = next(item for item in fresh["elements"] if item["name"] == "Region")
        filled = await FillTool(tool.elements, timeout_ms=3000, page_events=tool.page_events).execute(
            fill_action(field["element_id"], fresh["state_id"]))
        assert filled["status"] == "success" and await page.locator("input").input_value() == _PRESETS["dummy_text"]
        assert result["after_state_id"] is None
    asyncio.run(with_page(site, check))
