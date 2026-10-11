"""The unified public query, including selected data and actual SDK delivery."""
import asyncio
from copy import deepcopy
import json

import pytest
from pydantic import ValidationError

from page_query_support import make_query_tool
from sdk_tool_checks import run_native_steps
from l4_orchestrator.page_events import PageEvents
from l4_orchestrator.page_state import PageState, PageStateError
from l4_orchestrator.sdk_registry import register_native_tools
from l4_orchestrator.tools.click import ClickTool
from l4_orchestrator.tools.get_page_state import GetPageStateInput, GetPageStateTool
from test_click import action as click_action
from test_navigate import site, with_page
from test_page_state import query as state_query


HTML = '''<!doctype html><title>Query fixture</title><p>계정 확인 안내</p>
<a href="/login">Account</a><button onclick="window.clicks++">Continue</button>
<button hidden>Hidden</button>'''


def query(include=(), state_id=None, **params):
    request = state_query(state_id)
    request["params"] = {"include": list(include), **params}
    return request


async def make(page):
    await page.set_content(HTML)
    await page.evaluate("window.clicks=0; new Promise(requestAnimationFrame)")
    state = PageState(page, timeout_ms=3000)
    return make_query_tool(state)


def test_only_selected_collectors_run_and_each_new_query_refreshes_once(site, monkeypatch):
    async def check(page):
        tool = await make(page)
        counts = dict(refresh=0, content=0, elements=0)
        async def counted(name, original, *args, **kwargs):
            counts[name] += 1
            return await original(*args, **kwargs)
        for owner, attribute, name in ((tool.state, "refresh", "refresh"),
                                       (tool.content, "read", "content"),
                                       (tool.elements, "query", "elements")):
            original = getattr(owner, attribute)
            async def wrapper(*args, _name=name, _original=original, **kwargs):
                return await counted(_name, _original, *args, **kwargs)
            monkeypatch.setattr(owner, attribute, wrapper)
        before_html = await page.content()
        for include in ([], ["elements"], ["text"], ["links"], ["text", "links"],
                        ["text", "elements"], ["links", "elements"], ["text", "links", "elements"]):
            previous = counts.copy()
            reply = await tool.execute(query(include))
            assert reply["status"] == "success", reply
            data = reply["result"]
            assert data["title"] == "Query fixture" and data["state_id"] == tool.state.read()["state_id"]
            assert counts["refresh"] - previous["refresh"] == 1
            assert counts["content"] - previous["content"] == bool({"text", "links"} & set(include))
            assert counts["elements"] - previous["elements"] == ("elements" in include)
            assert ("elements" in data) == ("elements" in include)
            if "elements" in include:
                assert [item["name"] for item in data["elements"]] == ["Account", "Continue"]
                assert tool.elements._state_id == data["state_id"]
            if {"text", "links"} & set(include):
                assert (data["text"] is not None) == ("text" in include)
                assert (data["links"] is not None) == ("links" in include)
            else:
                assert "text" not in data and "links" not in data
        before_counts = counts.copy()
        listed = await tool.execute(query(scope="pages"))
        assert listed["status"] == "success" and counts == before_counts
        assert listed["after_state_id"] is None
        assert await page.content() == before_html and await page.evaluate("window.clicks") == 0
    asyncio.run(with_page(site, check))


def test_content_on_pinned_state_keeps_existing_elements_without_republishing(site, monkeypatch):
    async def check(page):
        tool = await make(page)
        first = (await tool.execute(query(["elements"])))["result"]
        published = tool.elements._published_ids.copy()
        async def unexpected(*args, **kwargs):
            raise AssertionError("A pinned text-only query must not refresh state or elements")
        monkeypatch.setattr(tool.state, "refresh", unexpected)
        monkeypatch.setattr(tool.elements, "query", unexpected)
        text = await tool.execute(query(["text"], first["state_id"]))
        assert text["status"] == "success" and text["result"]["state_id"] == first["state_id"]
        assert "elements" not in text["result"] and tool.elements._published_ids == published
        events = PageEvents(tool.state, on_event=lambda *args: None)
        click = ClickTool(tool.elements, timeout_ms=3000, page_events=events)
        button = next(item for item in first["elements"] if item["name"] == "Continue")
        reply = await click.execute(click_action(button["element_id"], first["state_id"]))
        assert reply["result"]["clicked"] is True and await page.evaluate("window.clicks") == 1
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("phase", ["after_content", "after_elements"])
def test_change_between_collectors_never_returns_mixed_success_or_action_ids(site, monkeypatch, phase):
    async def check(page):
        tool = await make(page)
        first = (await tool.execute(query(["elements"])))["result"]
        owner, method = (tool.content, "read") if phase == "after_content" else (tool.elements, "query")
        original, calls = getattr(owner, method), []
        async def change(*args, **kwargs):
            result = await original(*args, **kwargs)
            calls.append(True)
            await page.evaluate("document.querySelector('p').textContent = '다른 상태'")
            # Deliver the real DOM mutation notification before returning the collector.
            await page.evaluate("() => new Promise(requestAnimationFrame)")
            return result
        monkeypatch.setattr(owner, method, change)
        reply = await tool.execute(query(["text", "elements"], first["state_id"]))
        assert reply["status"] == "failed" and reply["error"]["code"] == "STATE_CHANGED"
        assert reply["result"] is None and reply["after_state_id"] is None and len(calls) == 1
        assert tool.elements._published_ids == set() and tool.elements._wait_ids == set()
        with pytest.raises(PageStateError):
            await tool.elements.resolve(first["elements"][0]["element_id"], expected_state_id=first["state_id"])
        monkeypatch.setattr(owner, method, original)
        recovered = await tool.execute(query(["text", "elements"]))
        assert recovered["status"] == "success" and "다른 상태" in recovered["result"]["text"]
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("ending", ["timeout", "cancel"])
def test_failed_combined_query_discards_old_element_list_even_before_element_collection(site, monkeypatch, ending):
    async def check(page):
        tool = await make(page)
        first = (await tool.execute(query(["elements"])))["result"]
        original, entered = tool.content._collect, asyncio.Event()
        async def blocked(*args):
            entered.set()
            await asyncio.Event().wait()
        monkeypatch.setattr(tool.content, "_collect", blocked)
        tool.content.timeout_ms = 50 if ending == "timeout" else 3000
        pending = asyncio.create_task(tool.execute(query(["text", "elements"], first["state_id"])))
        await entered.wait()
        if ending == "cancel":
            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pending
        else:
            reply = await pending
            assert reply["status"] == "timeout" and reply["result"] is None
        assert tool.elements._published_ids == set() and tool.elements._wait_ids == set()
        with pytest.raises(PageStateError):
            await tool.elements.resolve(first["elements"][0]["element_id"], expected_state_id=first["state_id"])
        monkeypatch.setattr(tool.content, "_collect", original)
        tool.content.timeout_ms = 3000
        assert (await tool.execute(query(["text", "elements"])))["status"] == "success"
    asyncio.run(with_page(site, check))


def test_public_schema_preserves_selected_input_and_rejects_old_names(site):
    for params in ({"include": ["html"]}, {"include": ["text", "text"]},
                   {"include": ["elements"], "visible_only": "false"},
                   {"include": ["text"], "visible_only": False},
                   {"scope": "pages", "include": ["elements"]}, {"kind": "both"}):
        with pytest.raises(ValidationError):
            GetPageStateInput.model_validate({**state_query(), "params": params})
    for params in ({}, {"scope": "page", "include": []},
                   {"include": ["elements"], "visible_only": True},
                   {"include": ["text", "elements"], "visible_only": False}):
        request = {**state_query(), "params": params}
        assert GetPageStateInput.model_validate(request).model_dump(mode="json") == request

    async def check(page):
        tool = await make(page)
        registry = register_native_tools({"get_page_state": tool})
        catalog = registry.catalog()
        assert set(catalog) == {"get_page_state"}
        assert "include" in catalog["get_page_state"]["model_input_schema"]["$defs"]["PageStateParams"]["properties"]
        for name in ("get_interactable_elements", "get_page_content"):
            with pytest.raises(ValueError, match="No native input"):
                register_native_tools({name: tool})
        other_state = PageState(page, timeout_ms=3000)
        with pytest.raises(ValueError, match="same PageState"):
            GetPageStateTool(other_state, elements=tool.elements, content=tool.content)
    asyncio.run(with_page(site, check))


def test_combined_query_to_sdk_store_next_model_and_click_uses_same_observation(site, tmp_path):
    async def check(page):
        await page.goto(site)
        tool = await make(page)
        await page.evaluate("document.cookie='query_session=kept'")
        original_html = await page.content()
        click = ClickTool(tool.elements, timeout_ms=3000,
                          page_events=PageEvents(tool.state, on_event=lambda *args: None))
        request = query(["text", "links", "elements"])
        supplied = deepcopy(request)
        async def after_query(previous):
            data = previous[0]["result"]
            assert previous[0]["status"] == "success"
            assert "계정 확인 안내" in data["text"] and data["links"][0]["resolved_url"] == site + "/login"
            assert tool.elements._state_id == data["state_id"] == tool.state.read()["state_id"]
            assert await page.content() == original_html
            button = next(item for item in data["elements"] if item["name"] == "Continue")
            return click_action(button["element_id"], data["state_id"])
        proof = await run_native_steps({"get_page_state": tool, "click": click},
                                      [("get_page_state", request), ("click", after_query)])
        assert request == supplied
        assert proof.results[1]["result"]["clicked"] is True and await page.evaluate("window.clicks") == 1
        assert "query_session=kept" in await page.evaluate("document.cookie")
        assert proof.prepared_inputs[0]["params"] == supplied["params"]
        assert proof.prepared_inputs[1]["context"]["state_id"] == proof.results[0]["after_state_id"]
        assert proof.manager_inputs[1]["new_results"][0]["data"] == proof.results[0]
        (tmp_path / "combined-query-evidence.json").write_text(json.dumps({
            "scope": "real browser and SDK; scripted model and memory AWS IO",
            "source_html": original_html, "supplied_input": supplied,
            "prepared_inputs": proof.prepared_inputs, "results": proof.results,
            "next_manager_input": proof.manager_inputs[1], "model_inputs": proof.model_inputs,
            "page_clicks": await page.evaluate("window.clicks"),
        }, ensure_ascii=False, indent=2), encoding="utf-8")
    asyncio.run(with_page(site, check))
