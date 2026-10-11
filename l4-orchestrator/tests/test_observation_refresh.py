from page_query_support import make_query_tool
"""Query-driven observations on a real Page; no caller-side refresh calls."""
import asyncio
from copy import deepcopy

import pytest

pytest.importorskip("playwright.async_api")
from playwright.async_api import Error

from l4_orchestrator.elements import ElementRegistry
from l4_orchestrator.page_events import PageEvents
from l4_orchestrator.page_state import PageState, PageStateError
from l4_orchestrator.tools.click import ClickTool
from l4_orchestrator.tools.fill import FillTool, _PRESETS
from test_click import action as click_action
from test_fill import action as fill_action
from test_interactable_elements import query as elements_query
from test_navigate import site, with_page
from test_page_state import query as state_query


@pytest.mark.parametrize("state_first", [False, True])
def test_click_query_fill_without_manual_refresh_keeps_session_and_rejects_old_action(site, state_first):
    async def check(page):
        await page.goto(site)
        await page.set_content('''<button onclick="window.clicks++; document.querySelector('input').hidden=false">Open</button>
            <input aria-label="New field" hidden>''')
        await page.evaluate("window.clicks=0; window.sessionProof='same-document'; document.cookie='session=kept'")
        state = PageState(page, timeout_ms=3000)
        registry = ElementRegistry(state, timeout_ms=3000)
        states, elements = make_query_tool(state), make_query_tool(registry.state, elements=registry)
        events = PageEvents(state, on_event=lambda event, event_page: None)

        async def controls():
            state_id = None
            if state_first:
                snapshot = await states.execute(state_query())
                assert snapshot["status"] == "success", snapshot
                state_id = snapshot["result"]["state_id"]
            found = await elements.execute(elements_query(state_id))
            assert found["status"] == "success", found
            if state_first:
                assert found["result"]["state_id"] == state_id
            else:
                assert found["before_state_id"] is None
            return found["result"]

        first = await controls()
        assert [item["name"] for item in first["elements"]] == ["Open"]
        request = click_action(first["elements"][0]["element_id"], first["state_id"])
        click = ClickTool(registry, timeout_ms=3000, page_events=events)
        clicked = await click.execute(request)
        assert clicked["status"] == "success" and clicked["after_state_id"] is None
        original_result = deepcopy(clicked)
        for tool, query in ((states, state_query), (elements, elements_query)):
            stale = await tool.execute(query(first["state_id"]))
            assert stale["error"]["code"] == "STATE_CHANGED" and stale["result"] is None

        second = await controls()
        assert second["state_id"] != first["state_id"] and second["page_id"] == first["page_id"]
        assert [item["name"] for item in second["elements"]] == ["Open", "New field"]
        stale_action = await click.execute(request)
        assert stale_action["error"]["code"] == "TARGET_STALE"
        assert stale_action["result"]["clicked"] is False and await page.evaluate("window.clicks") == 1
        filled = await FillTool(registry, timeout_ms=3000, page_events=events).execute(
            fill_action(second["elements"][1]["element_id"], second["state_id"]))
        assert filled["status"] == "success" and filled["result"]["filled"] is True
        assert await page.locator("input").input_value() == _PRESETS["dummy_text"]
        assert await page.evaluate("window.sessionProof") == "same-document"
        assert "session=kept" in await page.evaluate("document.cookie")
        assert clicked == original_result  # A later query does not rewrite a previous action's result.
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("failure", ["timeout", "cancel"])
def test_failed_new_query_discards_old_state_and_next_query_can_recover(site, monkeypatch, failure):
    async def check(page):
        await page.set_content("<title>Initial</title><button>Continue</button>")
        state = PageState(page, timeout_ms=3000)
        tool = make_query_tool(state)
        first = (await tool.execute(state_query()))["result"]
        original_collect, tracking = state._collect, state._tracking_task
        started, calls = asyncio.Event(), []

        async def blocked_collect():
            calls.append(True)
            started.set()
            await asyncio.Event().wait()

        monkeypatch.setattr(state, "_collect", blocked_collect)
        state.timeout_ms = 50 if failure == "timeout" else 3000
        pending = asyncio.create_task(tool.execute(state_query()))
        await started.wait()
        if failure == "cancel":
            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pending
        else:
            result = await pending
            assert result["status"] == "timeout" and result["result"] is None
        assert len(calls) == 1  # No automatic retry.
        with pytest.raises(PageStateError):
            state.read(first["state_id"])
        monkeypatch.setattr(state, "_collect", original_collect)
        state.timeout_ms = 3000
        recovered = await tool.execute(state_query())
        assert recovered["status"] == "success", recovered
        assert recovered["result"]["title"] == "Initial"
        assert recovered["result"]["state_id"] != first["state_id"]
        assert state._tracking_task is tracking  # Do not register the browser binding again.
    asyncio.run(with_page(site, check))


def test_change_between_state_collection_and_element_collection_is_not_silently_retried(site, monkeypatch):
    async def check(page):
        await page.set_content("<button>Before</button>")
        state = PageState(page, timeout_ms=3000)
        registry = ElementRegistry(state, timeout_ms=3000)
        tool = make_query_tool(registry.state, elements=registry)
        first = (await tool.execute(elements_query()))["result"]
        original_collect, calls = registry._collect, []

        async def change_then_collect(snapshot, visible_only):
            calls.append(True)
            await page.evaluate("document.querySelector('button').textContent='After'")
            return await original_collect(snapshot, visible_only)

        monkeypatch.setattr(registry, "_collect", change_then_collect)
        changed = await tool.execute(elements_query())
        assert changed["status"] == "failed" and changed["error"]["code"] == "STATE_CHANGED"
        assert changed["result"] is None and len(calls) == 1
        with pytest.raises(PageStateError):
            await registry.resolve(first["elements"][0]["element_id"], expected_state_id=first["state_id"])
        monkeypatch.setattr(registry, "_collect", original_collect)
        recovered = await tool.execute(elements_query())
        assert recovered["status"] == "success" and recovered["result"]["elements"][0]["name"] == "After"
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("terminal, ending", [("closed", "return"), ("crash", "return"),
                                              ("crash", "error"), ("crash", "timeout")])
def test_terminal_event_during_new_query_stays_terminal(site, monkeypatch, terminal, ending):
    async def check(page):
        state = PageState(page, timeout_ms=3000)
        tool = make_query_tool(state)
        first = (await tool.execute(state_query()))["result"]
        original_collect, calls = state._collect, []

        async def terminated_collect():
            calls.append(True)
            observed = await original_collect()
            if terminal == "closed":
                await page.close()
            else:
                state._on_crash(page)  # Inject the crash callback; not a real browser crash.
                state.invalidate()  # A late change notification must not hide the crash.
            if ending == "error":
                raise Error("Protocol failure after crash")
            if ending == "timeout":
                raise TimeoutError()
            return observed

        monkeypatch.setattr(state, "_collect", terminated_collect)
        code = "PAGE_CLOSED" if terminal == "closed" else "BROWSER_CRASH"
        for state_id in (None, None, first["state_id"]):
            result = await tool.execute(state_query(state_id))
            assert result["status"] == "failed" and result["result"] is None
            assert result["error"]["code"] == code and result["error"]["recoverable"] is False
        assert len(calls) == 1
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("terminal", ["closed", "crash"])
def test_terminal_event_while_collecting_elements_is_not_a_recoverable_timeout(site, monkeypatch, terminal):
    async def check(page):
        await page.set_content("<button>Continue</button>")
        state = PageState(page, timeout_ms=3000)
        registry = ElementRegistry(state, timeout_ms=3000)
        tool = make_query_tool(registry.state, elements=registry)
        first = (await tool.execute(elements_query()))["result"]
        calls = []

        async def terminated_collect(*args):
            calls.append(True)
            if terminal == "closed":
                await page.close()
            else:
                state._on_crash(page)  # The crash notification is injected; the Page is real.
                state.invalidate()
            await asyncio.Event().wait()

        monkeypatch.setattr(registry, "_collect", terminated_collect)
        registry.timeout_ms = 300
        code = "PAGE_CLOSED" if terminal == "closed" else "BROWSER_CRASH"
        for _ in range(2):
            result = await tool.execute(elements_query())
            assert result["status"] == "failed" and result["result"] is None
            assert result["error"]["code"] == code and result["error"]["recoverable"] is False
        assert len(calls) == 1
        assert not registry._published_ids and registry._state_id is None
        with pytest.raises(PageStateError) as error:
            await registry.resolve(first["elements"][0]["element_id"], expected_state_id=first["state_id"])
        assert error.value.code == code
    asyncio.run(with_page(site, check))
