from sdk_tool_checks import run_native_steps
import asyncio
from copy import deepcopy

import pytest
from pydantic import ValidationError

playwright = pytest.importorskip("playwright.async_api", reason="Install the browser extra to run browser tests")

from l4_orchestrator.page_events import PageEvents
from l4_orchestrator.page_state import PageState, PageStateError
from l4_orchestrator.ports import Authorization
from l4_orchestrator.tools.click import ClickTool
from l4_orchestrator.tools.hover import HoverInput, HoverTool
from test_click import action as click_action
from test_interactable_elements import query, setup
from test_navigate import site, with_page
from test_page_state import wait_for_invalidation


MENU = '''<!doctype html><style>
body {margin:20px} #menu {width:220px} button {width:220px;height:44px}
#items {display:none} #menu:hover #items {display:block}
</style><div id="menu"><button id="trigger" onclick="window.triggerClicks=(window.triggerClicks||0)+1">Service</button>
<div id="items"><button id="download" onclick="window.downloadClicks=(window.downloadClicks||0)+1">Download</button></div></div>'''


def action(element_id="observed-id", state_id=None):
    return {"action_id": "hover-check", "tool": "hover", "target": {"element_id": element_id},
            "params": {}, "context": {"job_id": "local-check", "scenario_id": "hover",
                                      "step_id": "show-menu", "state_id": state_id}}


async def observed(page, html=MENU, *, timeout_ms=3000, callback=None):
    state, registry, query_tool = await setup(page, html)
    result = await query_tool.execute(query(visible_only=False))
    assert result["status"] == "success", result
    element_id = result["result"]["elements"][0]["element_id"]
    events = []
    bridge = PageEvents(state, on_event=callback or (
        lambda event, event_page: events.append((event, event_page))))
    tool = HoverTool(registry, timeout_ms=timeout_ms, page_events=bridge)
    return state, tool, action(element_id, state.read()["state_id"]), events, query_tool


def test_css_menu_without_dom_change_stays_open_through_observation_then_child_click(site):
    async def check(page):
        state, tool, request, events, query_tool = await observed(page)
        source = await page.content()
        page_id = state.page_id
        assert not await page.locator("#items").is_visible()
        result = await tool.execute(request)
        assert result["status"] == "success" and result["result"]["hovered"] is True
        assert await page.locator("#items").is_visible() and await page.content() == source
        assert await page.evaluate("window.triggerClicks || 0") == 0
        assert await page.locator("#trigger").evaluate("node => node.matches(':hover')")
        assert result["before_state_id"] == request["context"]["state_id"]
        assert result["after_state_id"] is None and result["observer_refs"] == {"l2": [], "l3": []}
        with pytest.raises(PageStateError):
            state.read()
        click = ClickTool(tool.elements, timeout_ms=3000, page_events=tool.page_events)
        stale = await click.execute(click_action(request["target"]["element_id"], request["context"]["state_id"]))
        assert stale["error"]["code"] == "TARGET_STALE" and stale["result"]["clicked"] is False
        after = await state.refresh()
        found = await query_tool.execute(query(after["state_id"]))
        by_name = {item["name"]: item for item in found["result"]["elements"]}
        assert by_name["Service"]["element_id"] == request["target"]["element_id"]
        assert after["state_id"] != request["context"]["state_id"] and state.page_id == page_id
        assert await page.locator("#trigger").evaluate("node => node.matches(':hover')")
        assert await page.locator("#items").is_visible()
        clicked = await click.execute(click_action(by_name["Download"]["element_id"], after["state_id"]))
        assert clicked["result"]["clicked"] is True
        assert await page.evaluate("[window.triggerClicks||0,window.downloadClicks||0]") == [0, 1]
        assert tool.elements.page is page and click.elements.page is page and events == []
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("attribute", ["disabled", 'aria-disabled="true"'])
def test_disabled_control_can_show_hover_description_without_click(site, attribute):
    async def check(page):
        html = '<style>button{margin:30px;width:200px;height:50px}p{display:none}button:hover+p{display:block}</style>' + f'<button {attribute}>Unavailable</button><p>Reason</p>'
        state, tool, request, events, query_tool = await observed(page, html)
        assert not await page.locator("p").is_visible()
        result = await tool.execute(request)
        assert result["status"] == "success" and result["result"]["hovered"] is True
        assert await page.locator("p").is_visible()
    asyncio.run(with_page(site, check))


def test_hover_can_create_new_menu_nodes_for_later_query(site):
    async def check(page):
        html = '<button style="margin:30px" onmouseenter="if(!document.querySelector(\'#new\'))this.insertAdjacentHTML(\'afterend\',\'<button id=new>New action</button>\')">Open</button>'
        state, tool, request, events, query_tool = await observed(page, html)
        result = await tool.execute(request)
        assert result["status"] == "success" and result["result"]["hovered"] is True
        await page.locator("#new").wait_for(state="visible")
        await state.refresh()
        found = await query_tool.execute(query())
        assert [item["name"] for item in found["result"]["elements"]] == ["Open", "New action"]
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("html", [
    '<button style="display:none">Hidden</button>',
    '<button style="visibility:hidden">Hidden</button>',
    '<button style="position:absolute;top:3000px">Below viewport</button>',
    '<button style="position:absolute;left:3000px">Outside horizontally</button>',
])
def test_hidden_or_offscreen_rejected_without_scrolling_or_invalidation(site, html):
    async def check(page):
        state, tool, request, events, query_tool = await observed(page, html)
        before = state.read()
        result = await tool.execute(request)
        assert result["error"]["code"] == "ELEMENT_NOT_VISIBLE" and result["result"]["hovered"] is False
        assert state.read() == before and await page.evaluate("[scrollX,scrollY]") == [0, 0]
    asyncio.run(with_page(site, check))


def test_clipped_inner_container_does_not_scroll_to_target(site):
    async def check(page):
        # Target's box intersects the viewport but is clipped by the small container.
        html = '<div id="box" style="position:absolute;top:20px;height:80px;overflow:auto"><div style="height:200px"></div><button>Clipped</button></div>'
        state, tool, request, events, query_tool = await observed(page, html, timeout_ms=400)
        result = await tool.execute(request)
        assert result["status"] != "success" and result["result"]["hovered"] is not True
        assert await page.evaluate("[scrollX,scrollY,document.querySelector('#box').scrollTop]") == [0, 0, 0]
    asyncio.run(with_page(site, check))


def test_unknown_stale_and_replacement_nodes_are_not_used(site):
    async def check(page):
        state, tool, request, events, query_tool = await observed(page)
        wrong = deepcopy(request)
        wrong["target"]["element_id"] = "not-published"
        result = await tool.execute(wrong)
        assert result["error"]["code"] == "ELEMENT_NOT_FOUND" and result["result"]["hovered"] is False
        wrong = deepcopy(request)
        wrong["context"]["state_id"] = "another-observation"
        result = await tool.execute(wrong)
        assert result["error"]["code"] == "TARGET_STALE" and result["result"]["hovered"] is False
        await page.locator("#trigger").evaluate("node => node.replaceWith(node.cloneNode(true))")
        await wait_for_invalidation(state)
        result = await tool.execute(request)
        assert result["error"]["code"] == "TARGET_STALE" and result["result"]["hovered"] is False
        assert not await page.locator("#items").is_visible()
    asyncio.run(with_page(site, check))


def test_overlay_timeout_does_not_force_or_click(site):
    async def check(page):
        state, tool, request, events, query_tool = await observed(
            page, MENU + '<div style="position:fixed;inset:0;z-index:99"></div>', timeout_ms=400)
        result = await tool.execute(request)
        assert result["status"] == "timeout" and result["result"]["hovered"] is None
        assert not await page.locator("#items").is_visible()
        assert await page.evaluate("window.triggerClicks || 0") == 0
        with pytest.raises(PageStateError):
            state.read()
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("cancel", [False, True])
def test_timeout_or_cancel_after_pointer_move_does_not_undo_or_repeat(site, monkeypatch, cancel):
    async def check(page):
        state, tool, request, events, query_tool = await observed(page, timeout_ms=500)
        moved = asyncio.Event()
        calls = []
        original = playwright.ElementHandle.hover
        async def delayed_reply(node, **kwargs):
            calls.append(kwargs)
            await original(node, **kwargs)
            moved.set()
            await asyncio.sleep(5)
        monkeypatch.setattr(playwright.ElementHandle, "hover", delayed_reply)
        task = asyncio.create_task(tool.execute(request))
        await asyncio.wait_for(moved.wait(), 3)
        if cancel:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            result = await task
            assert result["status"] == "timeout" and result["result"]["hovered"] is None
        assert len(calls) == 1 and calls[0]["scroll"] == "none" and calls[0]["force"] is False
        assert await page.locator("#items").is_visible()
        assert await page.evaluate("window.triggerClicks || 0") == 0
        with pytest.raises(PageStateError):
            state.read()
        assert tool.page_events.begin("later") == []
        tool.page_events.end()
        await page.goto(site + "/after-hover")
        assert events[-1][0]["observed_during_action_id"] is None
    asyncio.run(with_page(site, check))


def test_late_page_navigation_is_delivered_after_hover_returns(site):
    async def check(page):
        await page.goto(site + "/source")
        html = f'<button style="margin:30px" onmouseenter="setTimeout(()=>location.href=\'{site}/destination\',250)">Next</button>'
        state, tool, request, events, query_tool = await observed(page, html)
        result = await tool.execute(request)
        assert result["status"] == "success" and result["result"]["hovered"] is True
        await page.wait_for_url(site + "/destination")
        assert len(events) == 1 and events[0][1] is page
        assert result["result"]["page_events"] == [event for event, _ in events if event["observed_during_action_id"] == request["action_id"]]
        assert tool.elements.page is page
    asyncio.run(with_page(site, check))


def test_menu_removed_after_observation_is_not_clicked(site):
    async def check(page):
        state, tool, request, events, query_tool = await observed(page)
        assert (await tool.execute(request))["result"]["hovered"] is True
        await state.refresh()
        found = await query_tool.execute(query())
        target = next(item for item in found["result"]["elements"] if item["name"] == "Download")
        click_request = click_action(target["element_id"], state.read()["state_id"])
        await page.locator("#download").evaluate("node => node.replaceWith(node.cloneNode(true))")
        await wait_for_invalidation(state)
        click = ClickTool(tool.elements, timeout_ms=1000, page_events=tool.page_events)
        result = await click.execute(click_request)
        assert result["error"]["code"] == "TARGET_STALE" and result["result"]["clicked"] is False
        assert await page.evaluate("window.downloadClicks || 0") == 0
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("params", [{"click_after": True}, {"force": True}, {"scroll": "auto"}])
def test_extra_actions_are_not_accepted(params):
    request = action()
    request["params"] = params
    with pytest.raises(ValidationError):
        HoverInput.model_validate(request)


def test_configuration_and_closed_page(site):
    async def check(page):
        state, tool, request, events, query_tool = await observed(page)
        for timeout_ms in (0, -1, True):
            with pytest.raises(ValueError):
                HoverTool(tool.elements, timeout_ms=timeout_ms, page_events=tool.page_events)
        other_state = PageState(page, timeout_ms=1000)
        other_events = PageEvents(other_state, on_event=lambda event, page: None)
        with pytest.raises(ValueError):
            HoverTool(tool.elements, timeout_ms=1000, page_events=other_events)
        other_events.close()
        await page.close()
        result = await tool.execute(request)
        assert result["error"]["code"] == "PAGE_CLOSED" and result["result"]["hovered"] is False
    asyncio.run(with_page(site, check))


def test_sdk_receives_hover_result_without_automatic_click(site):
    async def check(page):
        state, tool, request, events, query_tool = await observed(page)
        proof = await run_native_steps({"hover": tool}, [("hover", request)])
        assert proof.results[0]["result"]["hovered"] is True and await page.locator("#items").is_visible()
        assert await page.evaluate("window.triggerClicks || 0") == 0
        assert len(proof.actions) == 1
    asyncio.run(with_page(site, check))
