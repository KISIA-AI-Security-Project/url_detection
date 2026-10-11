from sdk_tool_checks import run_native_steps
import asyncio
from copy import deepcopy
import json

import pytest
pytest.importorskip("playwright.async_api", reason="Install the browser extra to run browser tests")
from playwright.async_api import ElementHandle, Error, JSHandle, TimeoutError as BrowserTimeoutError

from l4_orchestrator.page_events import PageEvents
from l4_orchestrator.page_state import PageStateError
from l4_orchestrator.ports import Authorization
from l4_orchestrator.tools.fill import FillTool, _PRESETS, _WATCH_INPUT
from test_interactable_elements import query, setup
from test_navigate import site, with_page
from test_page_state import wait_for_invalidation


def action(element_id, state_id, value_type="dummy_text", clear_first=True):
    return {"action_id": "fill-check", "tool": "fill", "target": {"element_id": element_id},
            "params": {"value_type": value_type, "clear_first": clear_first},
            "context": {"job_id": "local-check", "scenario_id": "fill", "step_id": "enter",
                        "state_id": state_id}}


async def observed(page, html, *, value_type="dummy_text", clear_first=True, timeout_ms=3000):
    state, registry, query_tool = await setup(page, html)
    result = await query_tool.execute(query(visible_only=False))
    assert result["status"] == "success", result
    element_id = result["result"]["elements"][0]["element_id"]
    request = action(element_id, state.read()["state_id"], value_type, clear_first)
    events = []
    page_events = PageEvents(state, on_event=lambda event, event_page: events.append((event, event_page)))
    return state, FillTool(registry, timeout_ms=timeout_ms, page_events=page_events), request, events


@pytest.mark.parametrize("value_type, input_type", [
    ("dummy_username", "text"), ("dummy_email", "email"), ("dummy_password", "password"),
    ("dummy_phone", "tel"), ("dummy_text", "search"), ("dummy_text", "url"), ("dummy_text", "textarea"),
])
def test_presets_replace_previous_content_and_invalidate_without_submitting(site, value_type, input_type):
    async def check(page):
        html = ("<textarea>Previous content</textarea>" if input_type == "textarea" else
                f'<input type="{input_type}" value="Previous content">')
        state, tool, request, events = await observed(
            page, '<form onsubmit="window.submissions++;return false">' + html + '</form>', value_type=value_type)
        await page.evaluate("window.inputs = 0; window.submissions = 0; document.addEventListener('input', () => window.inputs++)")
        result = await tool.execute(request)
        assert result["status"] == "success" and result["error"] is None
        assert result["result"]["filled"] is True and result["result"]["value_type"] == value_type
        assert await page.locator("input, textarea").input_value() == _PRESETS[value_type]
        assert await page.evaluate("window.inputs") == 1 and await page.evaluate("window.submissions") == 0
        with pytest.raises(PageStateError):
            state.read()
        assert result["before_state_id"] == request["context"]["state_id"] and result["after_state_id"] is None
        assert not any(value in json.dumps(result) for value in _PRESETS.values())
        repeated = await tool.execute(request)
        assert repeated["error"]["code"] == "TARGET_STALE" and repeated["result"]["filled"] is False
        assert await page.evaluate("window.inputs") == 1 and events == []
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("input_type", ["text", "email", "password", "tel", "url", "search", "textarea"])
def test_append_at_end_from_middle_selection_without_reading_existing_value(site, input_type, monkeypatch):
    async def check(page):
        previous = "First line\nSecond line" if input_type == "textarea" else "Existing"
        html = f'<textarea>{previous}</textarea>' if input_type == "textarea" else f'<input type="{input_type}" value="{previous}">'
        state, tool, request, events = await observed(page, html, clear_first=False)
        node = page.locator("input, textarea")
        await node.focus()
        await page.keyboard.press("Home")
        await page.keyboard.press("ArrowRight")
        await page.keyboard.press("Shift+ArrowRight")

        async def no_readback(*args, **kwargs):
            pytest.fail("The fill Tool must not read existing values into Python")

        monkeypatch.setattr(ElementHandle, "input_value", no_readback)
        result = await tool.execute(request)
        assert result["status"] == "success", result
        assert await node.input_value() == previous + _PRESETS["dummy_text"]
        assert previous not in json.dumps(result) and _PRESETS["dummy_text"] not in json.dumps(result)
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("html, code", [
    ('<input style="display:none">', "ELEMENT_NOT_VISIBLE"),
    ('<input disabled>', "ELEMENT_DISABLED"),
    ('<div inert><textarea></textarea></div>', "ELEMENT_DISABLED"),
    ('<div aria-disabled="TRUE"><input></div>', "ELEMENT_DISABLED"),
    ('<input readonly>', "BLOCKED_ACTION"),
    ('<textarea readonly></textarea>', "BLOCKED_ACTION"),
    ('<input aria-readonly="TRUE">', "BLOCKED_ACTION"),
    ('<input type="number">', "BLOCKED_ACTION"),
    ('<input type="date">', "BLOCKED_ACTION"),
    ('<input type="file">', "BLOCKED_ACTION"),
    ('<input type="checkbox">', "BLOCKED_ACTION"),
    ('<div contenteditable role="textbox">Editor</div>', "BLOCKED_ACTION"),
    ('<label role="textbox" for="other">Label</label><input id="other">', "BLOCKED_ACTION"),
])
def test_rejected_targets_do_not_receive_input(site, html, code):
    async def check(page):
        state, tool, request, events = await observed(page, html)
        await page.evaluate("window.inputs = 0; document.addEventListener('input', () => window.inputs++)")
        before = state.read()
        result = await tool.execute(request)
        assert result["status"] == "failed" and result["error"]["code"] == code
        assert result["result"]["filled"] is False
        assert await page.evaluate("window.inputs") == 0 and state.read() == before and events == []
    asyncio.run(with_page(site, check))


def test_invalid_dummy_type_arbitrary_strings_and_non_boolean_clear_are_rejected(site):
    async def check(page):
        state, tool, request, events = await observed(page, '<input value="Unchanged">')
        invalid_params = [
            {"value_type": "real_password", "clear_first": True},
            {"value_type": "dummy_password", "clear_first": True, "value": "Caller-secret-do-not-echo"},
            {"value_type": "dummy_text", "clear_first": "false"},
            {"value_type": "dummy_text", "clear_first": 0},
            {"value_type": "dummy_text", "clear_first": None},
        ]
        for params in invalid_params:
            invalid = {**request, "params": params}
            with pytest.raises(ValueError) as error:
                await tool.execute(invalid)
            assert "Caller-secret-do-not-echo" not in str(error.value)
            assert "real_password" not in str(error.value)
        assert await page.locator("input").input_value() == "Unchanged"
        assert state.read()["state_id"] == request["context"]["state_id"] and events == []
    asyncio.run(with_page(site, check))


def test_stale_unknown_and_closed_targets_are_distinct(site):
    async def check(page):
        state, tool, request, events = await observed(page, '<input value="Unchanged">')
        invalid = deepcopy(request)
        invalid["target"]["element_id"] = "unknown"
        assert (await tool.execute(invalid))["error"]["code"] == "ELEMENT_NOT_FOUND"
        invalid = deepcopy(request)
        invalid["context"]["state_id"] = "wrong-state"
        assert (await tool.execute(invalid))["error"]["code"] == "TARGET_STALE"
        await page.evaluate("const old = document.querySelector('input'); old.replaceWith(old.cloneNode(true))")
        await wait_for_invalidation(state)
        stale = await tool.execute(request)
        assert stale["error"]["code"] == "TARGET_STALE" and stale["result"]["filled"] is False
        assert await page.locator("input").input_value() == "Unchanged"
        await page.close()
        closed = await tool.execute(request)
        assert closed["error"]["code"] == "PAGE_CLOSED" and closed["result"]["filled"] is False
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("clear_first", [True, False])
def test_focus_handler_cannot_redirect_text_to_a_different_input(site, clear_first):
    async def check(page):
        state, tool, request, events = await observed(page,
            '<input id="target" onfocus="document.querySelector(\'#other\').focus()"><input id="other">',
            clear_first=clear_first)
        result = await tool.execute(request)
        assert result["error"]["code"] == "BLOCKED_ACTION" and result["result"]["filled"] is None
        assert await page.locator("#target").input_value() == await page.locator("#other").input_value() == ""
    asyncio.run(with_page(site, check))


def test_append_key_handler_cannot_send_text_to_another_input(site):
    async def check(page):
        state, tool, request, events = await observed(page,
            '<input id="target" onkeydown="document.querySelector(\'#other\').focus()"><input id="other">',
            clear_first=False)
        result = await tool.execute(request)
        assert result["error"]["code"] == "BLOCKED_ACTION" and result["result"]["filled"] is None
        assert await page.locator("#target").input_value() == await page.locator("#other").input_value() == ""
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("clear_first", [True, False])
def test_length_limit_rejected_before_any_partial_input(site, clear_first):
    async def check(page):
        state, tool, request, events = await observed(page, '<input maxlength="5" value="ABCD">',
                                                    clear_first=clear_first)
        before = state.read()
        result = await tool.execute(request)
        assert result["error"]["code"] == "BLOCKED_ACTION" and result["result"]["filled"] is False
        assert await page.locator("input").input_value() == "ABCD" and state.read() == before
    asyncio.run(with_page(site, check))


def test_prevented_email_end_key_does_not_claim_successful_append(site):
    async def check(page):
        state, tool, request, events = await observed(page,
            '<input type="email" value="Existing" onkeydown="event.preventDefault()">', clear_first=False)
        await page.locator("input").focus()  # Initially focused caret remains at its start.
        result = await tool.execute(request)
        assert result["error"]["code"] == "BLOCKED_ACTION" and result["result"]["filled"] is None
        assert await page.locator("input").input_value() == _PRESETS["dummy_text"] + "Existing"
    asyncio.run(with_page(site, check))


def test_site_rewrite_of_value_is_reported_without_retry(site):
    async def check(page):
        state, tool, request, events = await observed(page,
            '<input oninput="window.inputs = (window.inputs || 0) + 1; this.value = \'rewritten\'">')
        result = await tool.execute(request)
        assert result["error"]["code"] == "BLOCKED_ACTION" and result["result"]["filled"] is None
        assert await page.locator("input").input_value() == "rewritten" and await page.evaluate("window.inputs") == 1
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("behavior", ["move", "cancel", "move_and_stop"])
def test_same_existing_value_is_not_proof_of_input_to_the_target(site, behavior):
    async def check(page):
        handlers = {"move": "document.querySelector('#other').focus()",
                    "cancel": "event.preventDefault()",
                    "move_and_stop": "document.querySelector('#other').focus(); event.stopPropagation()"}
        state, tool, request, events = await observed(page,
            f'<input id="target" value="{_PRESETS["dummy_text"]}" onbeforeinput="{handlers[behavior]}">'
            '<input id="other">')
        result = await tool.execute(request)
        assert result["status"] == "failed" and result["result"]["filled"] is None
        assert result["error"]["code"] == "BLOCKED_ACTION"
        assert await page.locator("#target").input_value() == _PRESETS["dummy_text"]
        if behavior in {"move", "cancel"}:
            assert await page.locator("#other").input_value() == ""
        else:
            # A site's stopPropagation can bypass the bubble guard; the observed wrong
            # input must still prevent a success report. The Tool cannot undo site code.
            assert await page.locator("#other").input_value() == _PRESETS["dummy_text"]
        # The temporary guard must be gone after failure, so later caller-owned input works.
        await page.locator("#other").fill("After Tool")
        assert await page.locator("#other").input_value() == "After Tool"
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("interruption", ["timeout", "cancel"])
def test_interruption_while_install_response_is_pending_still_removes_listeners(site, monkeypatch, interruption):
    async def check(page):
        state, tool, request, events = await observed(page, '<input id="target"><input id="other">',
                                                    timeout_ms=500 if interruption == "timeout" else 3000)
        installed = asyncio.Event()
        original_evaluate = JSHandle.evaluate

        async def delayed_install_response(handle, expression, arg=None):
            result = await original_evaluate(handle, expression, arg)
            if expression == _WATCH_INPUT:
                installed.set()  # Real browser listeners are installed, Python is still waiting.
                await asyncio.Future()
            return result

        monkeypatch.setattr(JSHandle, "evaluate", delayed_install_response)
        task = asyncio.create_task(tool.execute(request))
        await asyncio.wait_for(installed.wait(), 2)
        if interruption == "cancel":
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            result = await task
            assert result["status"] == "timeout" and result["result"]["filled"] is None
        monkeypatch.setattr(JSHandle, "evaluate", original_evaluate)
        await page.locator("#other").fill("After Tool")
        assert await page.locator("#other").input_value() == "After Tool"
        assert await page.locator("#target").input_value() == ""
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("error_class", [Error, BrowserTimeoutError])
def test_browser_errors_after_actual_input_do_not_echo_values_or_retry(site, monkeypatch, error_class):
    async def check(page):
        state, tool, request, events = await observed(page, '<input>', value_type="dummy_password")
        await page.evaluate("window.inputs = 0; document.addEventListener('input', () => window.inputs++)")
        original_fill = ElementHandle.fill

        async def fill_then_error(node, value, **kwargs):
            await original_fill(node, value, **kwargs)
            raise error_class("Driver error includes " + value)

        monkeypatch.setattr(ElementHandle, "fill", fill_then_error)
        result = await tool.execute(request)
        assert result["status"] == ("timeout" if error_class is BrowserTimeoutError else "failed")
        assert result["result"]["filled"] is None
        assert await page.locator("input").input_value() == _PRESETS["dummy_password"]
        assert await page.evaluate("window.inputs") == 1
        assert _PRESETS["dummy_password"] not in json.dumps(result)
    asyncio.run(with_page(site, check))


def test_fill_event_url_is_omitted_even_when_page_copies_dummy_into_it(site, monkeypatch):
    async def check(page):
        await page.goto(site + "/")
        state, tool, request, events = await observed(page,
            '<input oninput="history.pushState({}, \'\', \'?q=\' + encodeURIComponent(this.value))">',
            value_type="dummy_email")
        original_fill = ElementHandle.fill

        async def fill_and_wait_for_notification(node, value, **kwargs):
            # Deterministically deliver this real navigation within the action interval.
            # A late notification is deliberately absent from the Tool's returned list.
            async with page.expect_event("framenavigated"):
                await original_fill(node, value, **kwargs)

        monkeypatch.setattr(ElementHandle, "fill", fill_and_wait_for_notification)
        result = await tool.execute(request)
        assert result["status"] == "success", result
        assert len(events) == 1 and events[0][0]["kind"] == "navigation"
        assert "l4-test%40example.com" in events[0][0]["url"]  # Caller feed retains actual browser state.
        report = result["result"]["page_events"][0]
        assert report["url"] is None and report["url_omitted"] is True
        assert "l4-test" not in json.dumps(result)
    asyncio.run(with_page(site, check))


def test_sdk_uses_preset_name_and_returns_result_without_dummy_text(site):
    async def check(page):
        state, tool, request, events = await observed(page, '<input type="email">', value_type="dummy_email")
        proof = await run_native_steps({"fill": tool}, [("fill", request)])
        assert proof.results[0]["result"]["filled"] is True
        assert await page.locator("input").input_value() == _PRESETS["dummy_email"]
        recorded = json.dumps([r.body() for r in proof.store.snapshot_records()])
        assert not any(value in recorded for value in _PRESETS.values())
    asyncio.run(with_page(site, check))
