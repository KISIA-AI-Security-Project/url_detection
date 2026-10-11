from sdk_tool_checks import run_native_steps
import asyncio
from copy import deepcopy
from time import perf_counter

import pytest
from pydantic import ValidationError

pytest.importorskip("playwright.async_api")
from playwright.async_api import ElementHandle, Error, JSHandle, TimeoutError as BrowserTimeoutError

from l4_orchestrator.page_events import PageEvents
from l4_orchestrator.page_state import PageState, PageStateError
from l4_orchestrator.ports import Authorization
from l4_orchestrator.tools.fill import FillTool, _PRESETS
from l4_orchestrator.tools.select_option import SelectOptionTool
from l4_orchestrator.tools.wait_for import WaitForInput, WaitForTool, _ELEMENT_STATUS
from test_click import action as click_action
from l4_orchestrator.tools.click import ClickTool
from test_fill import action as fill_action
from test_interactable_elements import query, setup
from test_navigate import site, with_page


def action(condition, state_id=None, element_id=None, *, timeout_ms=1500, **params):
    return {"action_id": "wait-condition", "tool": "wait_for",
            "target": {"element_id": element_id} if element_id is not None else None,
            "params": {"condition": condition, "timeout_ms": timeout_ms, **params},
            "context": {"job_id": "local-check", "scenario_id": "wait",
                        "step_id": "ready", "state_id": state_id}}


async def observed(page, html='<button>Continue</button>', *, limit=3000):
    state, registry, queries = await setup(page, html)
    found = await queries.execute(query(visible_only=False))
    assert found["status"] == "success", found
    events = []
    bridge = PageEvents(state, on_event=lambda event, event_page: events.append((event, event_page)))
    return state, WaitForTool(registry, max_timeout_ms=limit, page_events=bridge), found["result"], queries, events


def test_select_then_wait_through_sdk_without_refresh_then_fresh_query_fill(site):
    async def check(page):
        html = """<select aria-label="Country" onchange="setTimeout(()=>document.querySelector('input').hidden=false,150)">
            <option value="">Choose</option><option value="KR">Korea</option></select><input aria-label="Region" hidden>"""
        state, tool, found, queries, events = await observed(page, html)
        select, field = found["elements"]
        select_request = {"action_id": "select-country", "tool": "select_option",
                          "target": {"element_id": select["element_id"]}, "params": {"value": "KR"},
                          "context": {"job_id": "local-check", "scenario_id": "wait", "step_id": "select", "state_id": found["state_id"]}}
        wait_request = action("visible", found["state_id"], field["element_id"])
        proof = await run_native_steps({
            "select_option": SelectOptionTool(tool.elements, timeout_ms=3000, page_events=tool.page_events),
            "wait_for": tool}, [("select_option", select_request), ("wait_for", wait_request)])
        selected, waited = proof.results
        assert selected["result"]["selected_value"] == "KR"
        assert waited["result"]["satisfied"] is True and waited["error"] is None
        assert waited["before_state_id"] == found["state_id"] and waited["after_state_id"] is None
        assert await page.locator("input").is_visible() and events == []
        with pytest.raises(PageStateError):
            state.read(found["state_id"])
        stale_fill = await FillTool(tool.elements, timeout_ms=3000, page_events=tool.page_events).execute(
            fill_action(field["element_id"], found["state_id"]))
        assert stale_fill["error"]["code"] == "TARGET_STALE"
        fresh = (await queries.execute(query()))["result"]
        fresh_field = next(item for item in fresh["elements"] if item["name"] == "Region")
        filled = await FillTool(tool.elements, timeout_ms=3000, page_events=tool.page_events).execute(
            fill_action(fresh_field["element_id"], fresh["state_id"]))
        assert filled["status"] == "success" and await page.locator("input").input_value() == _PRESETS["dummy_text"]
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("condition", ["visible", "hidden"])
def test_delayed_element_condition_can_follow_unrelated_dom_change(site, condition):
    async def check(page):
        html = '<button' + (' hidden' if condition == "visible" else '') + '>Continue</button>'
        state, tool, found, queries, events = await observed(page, html)
        await page.evaluate("document.body.appendChild(document.createElement('p'))")
        await page.evaluate("condition=>{setTimeout(()=>{document.querySelector('button').hidden=condition==='hidden'},100)}", condition)
        result = await tool.execute(action(condition, found["state_id"], found["elements"][0]["element_id"]))
        assert result["status"] == "success" and result["result"]["satisfied"] is True, result
        assert await page.locator("button").is_visible() == (condition == "visible")
        assert tool.page_events._events is None
    asyncio.run(with_page(site, check))


def test_removed_original_satisfies_hidden_even_if_same_named_replacement_is_visible(site):
    async def check(page):
        state, tool, found, queries, events = await observed(page)
        await page.evaluate("const old=document.querySelector('button'); old.replaceWith(old.cloneNode(true))")
        result = await tool.execute(action("hidden", found["state_id"], found["elements"][0]["element_id"]))
        assert result["status"] == "success" and result["result"]["satisfied"] is True
        assert await page.locator("button").is_visible()  # Only the original node was removed.
        visible = await tool.execute(action("visible", found["state_id"], found["elements"][0]["element_id"]))
        assert visible["error"]["code"] == "TARGET_STALE" and visible["result"]["satisfied"] is None
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("condition", ["visible", "hidden"])
def test_original_document_replacement_is_not_hidden_success(site, condition):
    async def check(page):
        state, tool, found, queries, events = await observed(page)
        await page.goto(site + "/destination")
        result = await tool.execute(action(condition, found["state_id"], found["elements"][0]["element_id"]))
        assert result["error"]["code"] == "TARGET_STALE" and result["result"]["satisfied"] is None
        changed = await tool.execute(action("url_change", found["state_id"]))
        assert changed["status"] == "success" and changed["result"]["satisfied"] is True
    asyncio.run(with_page(site, check))


def test_same_document_push_state_preserves_wait_identity_but_not_action_permission(site):
    async def check(page):
        await page.goto(site)
        state, tool, found, queries, events = await observed(page)
        await page.evaluate("history.pushState({}, '', '?same-document=1')")
        request = action("visible", found["state_id"], found["elements"][0]["element_id"])
        result = await tool.execute(request)
        assert result["status"] == "success" and result["result"]["satisfied"] is True, result
        stale_click = await ClickTool(tool.elements, timeout_ms=3000, page_events=tool.page_events).execute(
            click_action(found["elements"][0]["element_id"], found["state_id"]))
        assert stale_click["error"]["code"] == "TARGET_STALE" and stale_click["result"]["clicked"] is False
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("condition, delayed", [("url_change", False), ("url_change", True), ("dom_change", False), ("dom_change", True)])
def test_change_compares_to_baseline_even_if_it_happened_before_wait(site, condition, delayed):
    async def check(page):
        await page.goto(site)
        state, tool, found, queries, events = await observed(page)
        change = "history.pushState({}, '', '?changed=1')" if condition == "url_change" else "document.body.appendChild(document.createElement('p'))"
        script = "() => {setTimeout(()=>{" + change + "},100)}" if delayed else "() => {" + change + "}"
        await page.evaluate(script)
        result = await tool.execute(action(condition, None if delayed else found["state_id"]))
        assert result["status"] == "success" and result["result"]["satisfied"] is True, result
        assert result["before_state_id"] == found["state_id"] and result["after_state_id"] is None
    asyncio.run(with_page(site, check))


def test_dom_change_survives_immediate_browser_navigation(site):
    async def check(page):
        await page.goto(site)
        state, tool, found, queries, events = await observed(page)
        await page.evaluate("url => {setTimeout(() => location.assign(url), 0)}", site + "/destination")
        result = await tool.execute(action("dom_change", found["state_id"], timeout_ms=2000))
        assert result["status"] == "success" and result["result"]["satisfied"] is True, result
        await page.wait_for_url(site + "/destination")
        assert await page.locator("p").inner_text() == "Loaded"
    asyncio.run(with_page(site, check))


def test_dom_change_context_loss_before_navigation_event_keeps_same_baseline(site, monkeypatch):
    async def check(page):
        await page.goto(site)
        state, tool, found, queries, events = await observed(page)
        original, version = page.evaluate, tool.elements._document_version
        samples, navigating = 0, None

        async def interrupted(expression, *args, **kwargs):
            nonlocal samples, navigating
            if expression == "() => document.documentElement?.outerHTML ?? null":
                samples += 1
                if samples == 1:
                    assert tool.elements._document_version == version
                    navigating = asyncio.create_task(page.goto(site + "/destination"))
                    raise Error("Page.evaluate: Execution context was destroyed, most likely because of a navigation")
            return await original(expression, *args, **kwargs)

        monkeypatch.setattr(page, "evaluate", interrupted)
        result = await tool.execute(action("dom_change", found["state_id"], timeout_ms=2000))
        await navigating
        assert samples >= 2 and result["status"] == "success", result
        assert result["before_state_id"] == found["state_id"] and result["result"]["satisfied"] is True
        assert state.read_comparison()["state_id"] == found["state_id"]
        with pytest.raises(PageStateError):
            state.read(found["state_id"])
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("error_kind", ["navigation", "other"])
def test_dom_read_errors_remain_bounded_and_do_not_mask_unrelated_failure(site, monkeypatch, error_kind):
    async def check(page):
        state, tool, found, queries, events = await observed(page)
        original, samples = page.evaluate, 0

        async def fail_read(expression, *args, **kwargs):
            nonlocal samples
            if expression == "() => document.documentElement?.outerHTML ?? null":
                samples += 1
                raise Error("Execution context was destroyed, most likely because of a navigation"
                            if error_kind == "navigation" else "Unexpected DOM read failure")
            return await original(expression, *args, **kwargs)

        monkeypatch.setattr(page, "evaluate", fail_read)
        start = perf_counter()
        result = await tool.execute(action("dom_change", found["state_id"], timeout_ms=120))
        assert perf_counter() - start < 1
        assert result["result"]["satisfied"] is None and tool.page_events._events is None
        if error_kind == "navigation":
            assert samples >= 2 and result["status"] == "timeout" and result["error"]["code"] == "ACTION_TIMEOUT"
        else:
            assert samples == 1 and result["status"] == "failed" and result["error"]["code"] == "INTERNAL_ERROR"
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("terminal", ["closed", "crash"])
def test_dom_navigation_context_loss_does_not_mask_known_terminal(site, monkeypatch, terminal):
    async def check(page):
        state, tool, found, queries, events = await observed(page)
        original = page.evaluate

        async def terminate(expression, *args, **kwargs):
            if expression == "() => document.documentElement?.outerHTML ?? null":
                if terminal == "closed":
                    await page.close()
                else:
                    state._on_crash(page)  # Callback injection, not an actual browser crash.
                raise Error("Execution context was destroyed, most likely because of a navigation")
            return await original(expression, *args, **kwargs)

        monkeypatch.setattr(page, "evaluate", terminate)
        result = await tool.execute(action("dom_change", found["state_id"], timeout_ms=120))
        assert result["status"] == "failed" and result["result"]["satisfied"] is None
        assert result["error"]["code"] == ("PAGE_CLOSED" if terminal == "closed" else "BROWSER_CRASH")
        assert result["error"]["recoverable"] is False and tool.page_events._events is None
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("condition", ["url_change", "dom_change", "visible", "hidden"])
def test_unmet_condition_times_out_without_claiming_false_or_retrying(site, condition):
    async def check(page):
        html = '<button' + (' hidden' if condition == "visible" else '') + '>Continue</button>'
        state, tool, found, queries, events = await observed(page, html)
        element = found["elements"][0]["element_id"] if condition in {"visible", "hidden"} else None
        result = await tool.execute(action(condition, found["state_id"], element, timeout_ms=120))
        assert result["status"] == "timeout" and result["error"]["code"] == "ACTION_TIMEOUT"
        assert result["result"]["satisfied"] is None and tool.page_events._events is None
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("change", ["invalidate", "resize", "property", "same_html_reload"])
def test_dom_change_is_html_difference_not_generic_invalidation(site, change):
    async def check(page):
        await page.goto(site)
        html = '<input type="checkbox">' if change != "same_html_reload" else None
        if html is None:
            state = PageState(page, timeout_ms=3000)
            from l4_orchestrator.elements import ElementRegistry
            registry = ElementRegistry(state, timeout_ms=3000)
            bridge = PageEvents(state, on_event=lambda event, event_page: None)
            tool = WaitForTool(registry, max_timeout_ms=3000, page_events=bridge)
            found = await state.refresh()
        else:
            state, tool, found, queries, events = await observed(page, html)
        if change == "invalidate":
            state.invalidate()
        elif change == "resize":
            await page.set_viewport_size({"width": 900, "height": 700})
        elif change == "property":
            await page.evaluate("document.querySelector('input').checked=true")
        else:
            await page.reload()
        result = await tool.execute(action("dom_change", found["state_id"], timeout_ms=120))
        assert result["status"] == "timeout" and result["result"]["satisfied"] is None, result
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("load_state", ["domcontentloaded", "load"])
def test_already_loaded_current_document_returns_without_baseline_collection(site, load_state):
    async def check(page):
        from l4_orchestrator.elements import ElementRegistry
        state = PageState(page, timeout_ms=3000)
        registry = ElementRegistry(state, timeout_ms=3000)
        events = PageEvents(state, on_event=lambda event, event_page: None)
        result = await WaitForTool(registry, max_timeout_ms=3000, page_events=events).execute(
            action("load_state", state=load_state))
        assert result["status"] == "success" and result["result"]["satisfied"] is True
        assert result["before_state_id"] is None and state._comparison is None
    asyncio.run(with_page(site, check))


def test_load_waits_for_current_document_slow_resource(site):
    async def check(page):
        async def controlled_document(route):
            await route.fulfill(body='<title>Delayed load</title><img src="/slow">', content_type="text/html")
        await page.route(site + "/load-test", controlled_document)
        await page.goto(site + "/load-test", wait_until="domcontentloaded")
        assert await page.evaluate("document.readyState") == "interactive"
        from l4_orchestrator.elements import ElementRegistry
        state = PageState(page, timeout_ms=3000)
        events = PageEvents(state, on_event=lambda event, event_page: None)
        result = await WaitForTool(ElementRegistry(state, timeout_ms=3000), max_timeout_ms=3000, page_events=events).execute(
            action("load_state", state="load"))
        assert result["status"] == "success" and await page.evaluate("document.readyState") == "complete"
    asyncio.run(with_page(site, check))


def test_fixed_time_waits_elapsed_duration_without_browser_input(site):
    async def check(page):
        state, tool, found, queries, events = await observed(page)
        source, start = await page.content(), perf_counter()
        result = await tool.execute(action("timeout", timeout_ms=120))
        assert perf_counter() - start >= 0.115
        assert result["status"] == "success" and result["result"]["satisfied"] is True
        assert await page.content() == source and events == [] and result["after_state_id"] is None
        with pytest.raises(PageStateError):
            state.read()
    asyncio.run(with_page(site, check))


def test_fixed_time_does_not_convert_timeout_exception_to_success(site, monkeypatch):
    async def check(page):
        state, tool, found, queries, events = await observed(page)
        def interrupted_begin(action_id):
            raise TimeoutError("Injected interruption, not elapsed time")
        monkeypatch.setattr(tool.page_events, "begin", interrupted_begin)
        result = await tool.execute(action("timeout", timeout_ms=120))
        assert result["status"] == "timeout" and result["result"]["satisfied"] is None
    asyncio.run(with_page(site, check))


def test_caller_limit_rejects_request_without_clamping_or_changing_state(site):
    async def check(page):
        state, tool, found, queries, events = await observed(page, limit=100)
        before = state.read()
        result = await tool.execute(action("timeout", timeout_ms=101))
        assert result["status"] == "blocked" and result["error"]["code"] == "BLOCKED_ACTION"
        assert result["result"]["satisfied"] is None and state.read() == before and events == []
    asyncio.run(with_page(site, check))


def test_input_condition_target_and_timeout_are_strict():
    for condition in ("visible", "hidden", "url_change", "dom_change", "load_state", "timeout"):
        valid = action(condition, element_id="el" if condition in {"visible", "hidden"} else None)
        WaitForInput.model_validate(valid)
    invalid = [action("visible"), action("hidden"), action("timeout", element_id="el"),
               action("dom_change", state="load"), action("load_state", state="networkidle"),
               action("unknown"), action("timeout", force=True)]
    invalid.extend(action("timeout", timeout_ms=n) for n in (0, -1, True, "100", 0.5, None))
    for request in invalid:
        with pytest.raises(ValidationError):
            WaitForInput.model_validate(request)


def test_unknown_target_missing_baseline_or_replaced_baseline_do_not_autocollect(site):
    async def check(page):
        state, tool, found, queries, events = await observed(page)
        unknown = await tool.execute(action("hidden", found["state_id"], "unknown"))
        assert unknown["error"]["code"] == "ELEMENT_NOT_FOUND" and unknown["result"]["satisfied"] is None
        fresh = (await queries.execute(query(visible_only=False)))["result"]
        assert fresh["state_id"] != found["state_id"]
        stale = await tool.execute(action("visible", found["state_id"], found["elements"][0]["element_id"]))
        assert stale["error"]["code"] == "TARGET_STALE"
        with pytest.raises(PageStateError):
            state.read_comparison("foreign-state")
        # A successful state-only query replaces the baseline but registers no new IDs.
        snapshot = await state.refresh()
        stale_list = await tool.execute(action("visible", snapshot["state_id"], fresh["elements"][0]["element_id"]))
        assert stale_list["error"]["code"] == "TARGET_STALE"
        state._comparison = None  # Represents the initial, not-yet-observed state.
        missing = await tool.execute(action("url_change"))
        assert missing["error"]["code"] == "TARGET_STALE" and state._comparison is None
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("failure", ["timeout", "cancel"])
def test_failed_new_collection_discards_comparison_and_original_element_reference(site, monkeypatch, failure):
    async def check(page):
        state, tool, found, queries, events = await observed(page)
        original, entered = state._collect, asyncio.Event()
        async def pending_collect():
            entered.set()
            await asyncio.Event().wait()
        monkeypatch.setattr(state, "_collect", pending_collect)
        state.timeout_ms = 50 if failure == "timeout" else 3000
        pending = asyncio.create_task(state.refresh())
        await entered.wait()
        if failure == "cancel":
            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pending
        else:
            with pytest.raises(PageStateError):
                await pending
        assert state._comparison is None
        for request in (action("url_change", found["state_id"]), action("hidden", found["state_id"], found["elements"][0]["element_id"])):
            result = await tool.execute(request)
            assert result["error"]["code"] == "TARGET_STALE" and result["result"]["satisfied"] is None
        monkeypatch.setattr(state, "_collect", original)
        state.timeout_ms = 3000
        recovered = (await queries.execute(query(visible_only=False)))["result"]
        assert recovered["state_id"] != found["state_id"]
        result = await tool.execute(action("visible", recovered["state_id"], recovered["elements"][0]["element_id"]))
        assert result["status"] == "success"
    asyncio.run(with_page(site, check))


def test_failed_element_query_does_not_reactivate_wait_targets(site, monkeypatch):
    async def check(page):
        state, tool, found, queries, events = await observed(page)
        async def fail_collect(snapshot, visible_only):
            raise TimeoutError("Injected failed element query")
        monkeypatch.setattr(tool.elements, "_collect", fail_collect)
        failed = await queries.execute(query(found["state_id"]))
        assert failed["status"] == "timeout"
        result = await tool.execute(action("hidden", found["state_id"], found["elements"][0]["element_id"]))
        assert result["error"]["code"] == "TARGET_STALE" and result["result"]["satisfied"] is None
    asyncio.run(with_page(site, check))


def test_cancel_releases_original_node_and_event_interval(site, monkeypatch):
    async def check(page):
        state, tool, found, queries, events = await observed(page, '<button hidden>Continue</button>')
        original_eval, original_dispose, entered, disposed = ElementHandle.evaluate, JSHandle.dispose, asyncio.Event(), []
        async def blocked_status(node, expression, *args, **kwargs):
            if expression == _ELEMENT_STATUS:
                entered.set()
                await asyncio.Event().wait()
            return await original_eval(node, expression, *args, **kwargs)
        async def dispose(handle):
            disposed.append(handle)
            await original_dispose(handle)
        monkeypatch.setattr(ElementHandle, "evaluate", blocked_status)
        monkeypatch.setattr(JSHandle, "dispose", dispose)
        pending = asyncio.create_task(tool.execute(action("visible", found["state_id"], found["elements"][0]["element_id"])))
        await entered.wait()
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
        assert len(disposed) == 1 and tool.page_events._events is None
        assert (await queries.execute(query()))["status"] == "success"
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("terminal", ["closed", "crash"])
def test_known_terminal_during_hidden_wait_overrides_timeout_or_removal(site, monkeypatch, terminal):
    async def check(page):
        state, tool, found, queries, events = await observed(page)
        original = ElementHandle.evaluate
        async def terminate(node, expression, *args, **kwargs):
            if expression == _ELEMENT_STATUS:
                if terminal == "closed":
                    await page.close()
                else:
                    state._on_crash(page)  # Callback injection, not an actual browser crash.
                raise BrowserTimeoutError("Interrupted")
            return await original(node, expression, *args, **kwargs)
        monkeypatch.setattr(ElementHandle, "evaluate", terminate)
        result = await tool.execute(action("hidden", found["state_id"], found["elements"][0]["element_id"]))
        assert result["status"] == "failed" and result["result"]["satisfied"] is None
        assert result["error"]["code"] == ("PAGE_CLOSED" if terminal == "closed" else "BROWSER_CRASH")
        assert result["error"]["recoverable"] is False and tool.page_events._events is None
    asyncio.run(with_page(site, check))
