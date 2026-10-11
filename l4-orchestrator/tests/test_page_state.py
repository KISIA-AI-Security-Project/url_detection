from page_query_support import make_query_tool
from sdk_tool_checks import run_native_steps
import asyncio
from copy import deepcopy
import hashlib

import pytest
from pydantic import ValidationError

pytest.importorskip("playwright.async_api", reason="Install the browser extra to run browser tests")

from l4_orchestrator.page_state import PageState, PageStateError
from l4_orchestrator.ports import Authorization
from test_navigate import action as navigation_action, make_tool, site, with_page


HTML = """<!doctype html><html><head><title>State check</title></head><body>
<form><input><button>Continue</button></form>
<form style="display:none"><input></form>
<div style="visibility:hidden">Hidden</div>
<div style="width:10px;height:10px;opacity:0"></div>
</body></html>"""


def query(state_id=None):
    return {"action_id": "state-check", "tool": "get_page_state", "target": None, "params": {},
            "context": {"job_id": "local-check", "scenario_id": "state", "step_id": "read",
                        "state_id": state_id}}


async def wait_for_invalidation(state):
    # Wait only for the change notification; do not refresh or read the browser DOM.
    for _ in range(100):
        try:
            state.read()
        except PageStateError as exc:
            assert exc.code == "STATE_CHANGED"
            return
        await asyncio.sleep(0.01)
    pytest.fail("A DOM change was not reported to the state holder")


def test_real_observation_then_read_without_recollection(site, monkeypatch):
    async def check(page):
        await page.set_content(HTML)
        state = PageState(page, timeout_ms=3000)
        first = await state.refresh()
        assert first["url"] == page.url and first["title"] == "State check"
        assert first["visible_element_count"] == 6 and first["form_count"] == 2
        source = await page.evaluate("document.documentElement.outerHTML")
        assert first["dom_fingerprint"] == "sha256:" + hashlib.sha256(source.encode()).hexdigest()
        assert first["active"] is True and first["observed_at"]
        assert first["observation_scope"] == "main_document_light_dom" and "html" not in first

        def must_not_collect(*args, **kwargs):
            pytest.fail("The read-only Tool tried to collect/update browser state")

        monkeypatch.setattr(page, "evaluate", must_not_collect)
        monkeypatch.setattr(state, "refresh", must_not_collect)
        tool = make_query_tool(state)
        for _ in range(2):
            result = await tool.execute(query(first["state_id"]))
            assert result["status"] == "success" and result["result"] == first
            assert result["before_state_id"] == result["after_state_id"] == first["state_id"]
        result["result"]["title"] = "Changed by caller"
        assert state.read()["title"] == "State check"
        invalid = query()
        invalid["params"]["save"] = True
        with pytest.raises(ValidationError):
            await tool.execute(invalid)
    asyncio.run(with_page(site, check))


def test_queries_collect_initial_state_and_after_dom_change_and_navigation(site):
    async def check(page):
        await page.set_content(HTML)
        state = PageState(page, timeout_ms=3000)
        tool = make_query_tool(state)
        initial = await tool.execute(query())
        assert initial["status"] == "success", initial
        first = initial["result"]
        assert initial["before_state_id"] is None and initial["after_state_id"] == first["state_id"]
        await page.evaluate("document.title = 'Changed'; document.body.appendChild(document.createElement('form'))")
        await wait_for_invalidation(state)
        stale = await tool.execute(query(first["state_id"]))
        assert stale["result"] is None and stale["error"]["code"] == "STATE_CHANGED"
        second = (await tool.execute(query()))["result"]
        assert second["title"] == "Changed" and second["form_count"] == 3
        assert second["state_id"] != first["state_id"] and second["page_id"] == first["page_id"]
        assert second["dom_fingerprint"] != first["dom_fingerprint"]
        assert (await tool.execute(query(first["state_id"])))["error"]["code"] == "STATE_CHANGED"

        navigation = await make_tool(page, site).execute(navigation_action(site + "/redirect"))
        assert navigation["status"] == "success" and navigation["after_state_id"] is None
        assert (await tool.execute(query(second["state_id"])))["error"]["code"] == "STATE_CHANGED"
        third = (await tool.execute(query()))["result"]
        assert third["url"] == site + "/destination" and third["page_id"] == first["page_id"]
        assert third["form_count"] == 0 and third["title"] == "Navigation check"
        await page.evaluate("document.title = 'After navigation'")
        await wait_for_invalidation(state)  # The watcher is also installed in the new document.
    asyncio.run(with_page(site, check))


def test_failed_refresh_does_not_return_previous_success(site, monkeypatch):
    async def check(page):
        await page.set_content(HTML)
        state = PageState(page, timeout_ms=3000)
        await state.refresh()
        monkeypatch.setattr("l4_orchestrator.page_state._COLLECT", "() => new Promise(() => {})")
        state.timeout_ms = 50
        with pytest.raises(PageStateError) as error:
            await state.refresh()
        assert error.value.code == "ACTION_TIMEOUT"
        result = await make_query_tool(state).execute(query())
        assert result["status"] == "timeout" and result["result"] is None
        await page.close()
        result = await make_query_tool(state).execute(query())
        assert result["status"] == "failed" and result["error"]["code"] == "PAGE_CLOSED"
    asyncio.run(with_page(site, check))


def test_state_reference_cannot_select_another_page(site):
    async def check(page):
        other_page = await page.context.new_page()
        await page.set_content(HTML)
        await other_page.set_content("<title>Other page</title>")
        state, other_state = PageState(page, timeout_ms=3000), PageState(other_page, timeout_ms=3000)
        first, other = await state.refresh(), await other_state.refresh()
        assert first["page_id"] != other["page_id"]
        tool = make_query_tool(state)
        result = await tool.execute(query(other["state_id"]))
        assert result["error"]["code"] == "STATE_CHANGED" and result["result"] is None
        assert (await tool.execute(query(first["state_id"])))["result"] == first
        fresh = (await tool.execute(query()))["result"]
        assert fresh["page_id"] == first["page_id"] and fresh["state_id"] != first["state_id"]
        assert fresh["title"] == "State check"
    asyncio.run(with_page(site, check))


def test_first_refresh_timeout_can_be_followed_by_an_explicit_refresh(site):
    async def check(page):
        await page.set_content(HTML)
        state = PageState(page, timeout_ms=1)
        with pytest.raises(PageStateError) as error:
            await state.refresh()
        assert error.value.code == "ACTION_TIMEOUT"
        state.timeout_ms = 3000
        observed = await state.refresh()
        assert observed["title"] == "State check" and observed["form_count"] == 2
        assert (await make_query_tool(state).execute(query(observed["state_id"])))["result"] == observed
    asyncio.run(with_page(site, check))


def test_observed_state_through_sdk(site):
    async def check(page):
        navigation = await make_tool(page, site).execute(navigation_action(site + "/redirect"))
        state = PageState(page, timeout_ms=3000)
        proof = await run_native_steps({"get_page_state": make_query_tool(state)},
                                       [("get_page_state", query())])
        observed = proof.results[0]["result"]
        assert observed == state.read() and observed["url"] == site + "/destination"
        assert proof.prepared_inputs[0]["context"]["state_id"] is None
        assert navigation["after_state_id"] is None
    asyncio.run(with_page(site, check))
