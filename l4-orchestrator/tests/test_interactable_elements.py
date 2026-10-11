from page_query_support import make_query_tool
from sdk_tool_checks import run_native_steps
import asyncio
from copy import deepcopy

import pytest
from pydantic import ValidationError

pytest.importorskip("playwright.async_api", reason="Install the browser extra to run browser tests")

from l4_orchestrator.elements import ElementRegistry
from l4_orchestrator.page_state import PageState, PageStateError
from l4_orchestrator.ports import Authorization
from test_navigate import site, with_page
from test_page_state import wait_for_invalidation


HTML = """<!doctype html><html><head><title>Elements</title></head><body>
<label for="email">Email address</label><input id="email" value="do-not-return">
<label>Password <input id="password" type="password" value="secret"></label>
<span id="first" hidden>First</span><span id="last">Last</span>
<button id="labelled" aria-label="Ignored" aria-labelledby="last first">Visual text</button>
<button id="aria" aria-label="Accessible name">Visible text</button>
<a href="/destination">Destination</a><textarea aria-label="Message">initial value</textarea>
<select aria-label="Choice"><option>A</option><option>B</option></select>
<label><input type="checkbox">Agree</label><input type="radio" aria-label="Option">
<div role="button" aria-label="Custom button" tabindex="0">Custom</div>
<button role="future-role button">Fallback native</button>
<div role="future-role button" tabindex="0">Fallback custom</div>
<button role="unknown-only">Implicit fallback</button>
<div role="article button" tabindex="0">First valid role wins</div>
<button id="hidden" style="display:none">Hidden button</button>
<input type="hidden" name="csrf" value="hidden-value">
<button id="disabled" disabled>Disabled</button>
<fieldset disabled><legend><button id="legend">Legend exception</button></legend>
  <input id="field" aria-label="Disabled field">
</fieldset>
<div aria-disabled="true"><button id="aria-disabled">ARIA disabled</button>
  <button id="aria-enabled" aria-disabled="false">ARIA enabled</button></div>
<button id="upper-disabled" aria-disabled="TRUE">Upper disabled</button>
<div aria-disabled="TrUe"><button>Inherited upper disabled</button>
  <button aria-disabled="FALSE">Upper enabled</button></div>
<div inert><button id="inert">Inert button</button></div>
<input id="readonly" readonly aria-label="Read only">
<div id="shadow-host"></div><iframe srcdoc="<button>Frame button</button>"></iframe>
</body></html>"""


def query(state_id=None, visible_only=True):
    return {"action_id": "elements-check", "tool": "get_page_state", "target": None,
            "params": {"include": ["elements"], "visible_only": visible_only},
            "context": {"job_id": "local-check", "scenario_id": "elements", "step_id": "read",
                        "state_id": state_id}}


async def setup(page, html=HTML):
    await page.set_content(html)
    # A new browser can deliver its initial viewport resize after set_content.
    # Observe after the first rendering opportunity, not across that resize.
    await page.evaluate("() => new Promise(requestAnimationFrame)")
    state = PageState(page, timeout_ms=3000)
    await state.refresh()
    registry = ElementRegistry(state, timeout_ms=3000)
    return state, registry, make_query_tool(registry.state, elements=registry)


def test_names_roles_visibility_and_enabled_from_real_dom(site):
    async def check(page):
        await page.set_content(HTML)
        await page.frame_locator("iframe").locator("button").wait_for()
        await page.evaluate("document.querySelector('#shadow-host').attachShadow({mode:'open'}).innerHTML = '<button>Shadow button</button>'")
        await page.evaluate("() => new Promise(requestAnimationFrame)")
        state = PageState(page, timeout_ms=3000)
        first = await state.refresh()
        registry = ElementRegistry(state, timeout_ms=3000)
        tool = make_query_tool(registry.state, elements=registry)
        source = await page.content()
        result = await tool.execute(query(first["state_id"]))
        assert result["status"] == "success", result["error"]
        data = result["result"]
        by_name = {item["name"]: item for item in data["elements"]}
        assert by_name["Email address"]["role"] == "textbox"
        assert by_name["Password"]["role"] == "input"  # No implicit ARIA role for password input.
        assert by_name["Last First"]["text"] == "Visual text"
        assert by_name["Accessible name"]["text"] == "Visible text"
        assert by_name["Agree"]["role"] == "checkbox" and by_name["Option"]["role"] == "radio"
        assert by_name["Choice"]["role"] == "combobox" and by_name["Destination"]["role"] == "link"
        assert by_name["Custom button"]["role"] == "button"
        for name in ("Fallback native", "Fallback custom", "Implicit fallback"):
            assert by_name[name]["role"] == "button"
        assert not any(item["text"] == "First valid role wins" for item in data["elements"])
        assert by_name["Message"]["text"] == by_name["Email address"]["text"] == by_name["Password"]["text"] == ""
        for name in ("Disabled", "Disabled field", "ARIA disabled", "Inert button",
                     "Upper disabled", "Inherited upper disabled"):
            assert by_name[name]["enabled"] is False
        assert by_name["Legend exception"]["enabled"] is True
        assert by_name["ARIA enabled"]["enabled"] is True
        assert by_name["Upper enabled"]["enabled"] is True
        assert await page.locator("#upper-disabled").is_enabled() is False
        assert by_name["Read only"]["enabled"] is True  # enabled does not mean editable.
        assert all(item["visible"] for item in data["elements"])
        assert not ({"Hidden button", "Frame button", "Shadow button"} & by_name.keys())
        assert data["observation_scope"] == "main_document_light_dom" and data["observed_at"]
        assert data["page_id"] == first["page_id"] and data["state_id"] == first["state_id"]
        assert await page.content() == source and state.read() == first  # No injected ID attributes or refresh.
        assert "secret" not in str(data) and "do-not-return" not in str(data) and "hidden-value" not in str(data)
        all_result = await tool.execute(query(visible_only=False))
        assert all_result["status"] == "success", all_result["error"]
        hidden = [item for item in all_result["result"]["elements"] if item["text"] == "Hidden button"]
        assert len(hidden) == 1 and hidden[0]["visible"] is False
        assert hidden[0]["name"] == ""  # Normal accessible-name rules still apply to hidden candidates.
        assert len(all_result["result"]["elements"]) == len(data["elements"]) + 1
    asyncio.run(with_page(site, check))


def test_node_identity_survives_requery_but_not_replacement(site):
    async def check(page):
        state, registry, tool = await setup(page, '<button id="one">Same</button><button id="two">Same</button>')
        first = await tool.execute(query())
        first_ids = [item["element_id"] for item in first["result"]["elements"]]
        assert len(set(first_ids)) == 2
        second = await tool.execute(query())
        assert [item["element_id"] for item in second["result"]["elements"]] == first_ids
        assert second["result"]["state_id"] != first["result"]["state_id"]
        node = await registry.resolve(first_ids[0], expected_state_id=state.read()["state_id"])
        assert await node.get_attribute("id") == "one"
        await node.dispose()
        old_state_id = state.read()["state_id"]
        await page.evaluate("document.querySelector('#one').textContent = 'Renamed'")
        await wait_for_invalidation(state)
        assert (await tool.execute(query(old_state_id)))["error"]["code"] == "STATE_CHANGED"
        updated = await tool.execute(query())
        assert updated["result"]["elements"][0]["element_id"] == first_ids[0]
        assert updated["result"]["elements"][0]["name"] == "Renamed"
        with pytest.raises(PageStateError, match="state"):
            await registry.resolve(first_ids[0], expected_state_id=old_state_id)

        await page.evaluate("const old = document.querySelector('#one'); old.replaceWith(old.cloneNode(true))")
        await wait_for_invalidation(state)
        await state.refresh()
        # Refreshing PageState alone does not turn old element observations into current ones.
        with pytest.raises(PageStateError):
            await registry.resolve(first_ids[0], expected_state_id=state.read()["state_id"])
        replaced = await tool.execute(query())
        replacement_id = replaced["result"]["elements"][0]["element_id"]
        assert replacement_id != first_ids[0]
        assert replaced["result"]["elements"][1]["element_id"] == first_ids[1]
        with pytest.raises(PageStateError):
            await registry.resolve(first_ids[0], expected_state_id=state.read()["state_id"])
        await page.evaluate("document.querySelector('#two').remove()")
        await wait_for_invalidation(state)
        await state.refresh()
        assert len((await tool.execute(query()))["result"]["elements"]) == 1
        with pytest.raises(PageStateError):
            await registry.resolve(first_ids[1], expected_state_id=state.read()["state_id"])
    asyncio.run(with_page(site, check))


def test_other_page_navigation_and_page_closed(site):
    async def check(page):
        state, registry, tool = await setup(page, '<button>Continue</button>')
        first = (await tool.execute(query()))["result"]
        first_id = first["elements"][0]["element_id"]
        other_page = await page.context.new_page()
        other_state, other_registry, other_tool = await setup(other_page, '<button>Continue</button>')
        other = (await other_tool.execute(query()))["result"]
        assert other["elements"][0]["element_id"] != first_id
        with pytest.raises(PageStateError):
            await other_registry.resolve(first_id, expected_state_id=other_state.read()["state_id"])
        assert (await tool.execute(query(other["state_id"])))["error"]["code"] == "STATE_CHANGED"
        await page.goto(site + "/destination")
        assert (await tool.execute(query(first["state_id"])))["error"]["code"] == "STATE_CHANGED"
        navigated = await tool.execute(query())
        assert navigated["status"] == "success" and navigated["result"]["elements"] == []
        await page.set_content('<button>Continue</button>')
        after = await tool.execute(query())
        assert after["status"] == "success", after
        assert after["result"]["page_id"] == first["page_id"]
        assert after["result"]["elements"][0]["element_id"] != first_id
        with pytest.raises(PageStateError):
            await registry.resolve(first_id, expected_state_id=state.read()["state_id"])
        await page.close()
        closed = await tool.execute(query())
        assert closed["result"] is None and closed["error"]["code"] == "PAGE_CLOSED"
    asyncio.run(with_page(site, check))


def test_empty_success_invalid_input_and_timeout_are_distinct(site, monkeypatch):
    async def check(page):
        state, registry, tool = await setup(page, '<p>No controls</p>')
        empty = await tool.execute(query())
        assert empty["status"] == "success" and empty["result"]["elements"] == []
        for invalid_value in ("false", 0, None):
            with pytest.raises(ValidationError):
                await tool.execute(query(visible_only=invalid_value))
        invalid = query()
        invalid["params"]["save"] = True
        with pytest.raises(ValidationError):
            await tool.execute(invalid)
        await page.set_content('<button>Before timeout</button>')
        await state.refresh()
        previous = (await tool.execute(query()))["result"]["elements"][0]["element_id"]
        original_collect = registry._collect

        async def slow_collect(*args):
            await asyncio.sleep(1)
            return await original_collect(*args)

        monkeypatch.setattr(registry, "_collect", slow_collect)
        registry.timeout_ms = 20
        timed_out = await tool.execute(query())
        assert timed_out["status"] == "timeout" and timed_out["result"] is None
        assert timed_out["error"]["code"] == "ACTION_TIMEOUT"
        with pytest.raises(PageStateError):
            await registry.resolve(previous, expected_state_id=state.read()["state_id"])
        monkeypatch.setattr(registry, "_collect", original_collect)
        registry.timeout_ms = 3000
        assert (await tool.execute(query()))["status"] == "success"
    asyncio.run(with_page(site, check))


def test_changed_dom_is_rejected_even_before_change_notification(site):
    async def check(page):
        state, registry, tool = await setup(page, '<button>Before</button>')
        first = await tool.execute(query())
        # Disconnect only the notification mechanism to isolate the hash guard.
        await page.evaluate("name => window[name + '_observer'].disconnect()", state._binding)
        await page.evaluate("document.querySelector('button').textContent = 'After'")
        assert state.read()["state_id"] == first["result"]["state_id"]
        changed = await tool.execute(query(first["result"]["state_id"]))
        assert changed["status"] == "failed" and changed["error"]["code"] == "STATE_CHANGED"
        assert changed["result"] is None
        fresh = await tool.execute(query())
        assert fresh["status"] == "success" and fresh["result"]["elements"][0]["name"] == "After"
    asyncio.run(with_page(site, check))


def test_sdk_preserves_element_output_in_store_and_next_manager_input(site):
    async def check(page):
        state, registry, tool = await setup(page, '<button>Continue</button>')
        proof = await run_native_steps({"get_page_state": tool},
            [("get_page_state", query(state.read()["state_id"]))])
        assert proof.results[0]["result"]["elements"][0]["name"] == "Continue"
        assert proof.manager_inputs[1]["new_results"][0]["data"] == proof.results[0]
    asyncio.run(with_page(site, check))
