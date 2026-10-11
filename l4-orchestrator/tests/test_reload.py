from sdk_tool_checks import run_native_steps
import asyncio
from copy import deepcopy

import pytest
from pydantic import ValidationError

pytest.importorskip("playwright.async_api")

from l4_orchestrator.elements import ElementRegistry
from l4_orchestrator.page_events import PageEvents
from l4_orchestrator.page_state import PageState, PageStateError
from l4_orchestrator.ports import Authorization
from l4_orchestrator.tools.click import ClickTool
from l4_orchestrator.tools.reload import ReloadInput, ReloadTool
from test_click import action as click_action
from test_navigate import site, with_page


def action(state_id=None, wait_until="domcontentloaded"):
    return {"action_id": "reload-check", "tool": "reload", "target": None,
            "params": {"wait_until": wait_until},
            "context": {"job_id": "local-check", "scenario_id": "reload",
                        "step_id": "observe-after-reload", "state_id": state_id}}


async def observed(page, *, timeout_ms=3000, on_event=None):
    await page.evaluate("() => new Promise(requestAnimationFrame)")
    state = PageState(page, timeout_ms=2000)
    snapshot = await state.refresh()
    delivered = []
    events = PageEvents(state, on_event=on_event or (
        lambda event, source: delivered.append((event, source))))
    return state, ReloadTool(state, timeout_ms=timeout_ms, page_events=events), action(snapshot["state_id"]), delivered


@pytest.mark.parametrize("wait_until", ["commit", "domcontentloaded", "load", "networkidle"])
def test_reload_once_reuses_page_and_session_without_automatic_observation(site, wait_until, monkeypatch):
    async def check(page):
        visits = 0

        async def content(route):
            nonlocal visits
            visits += 1
            await route.fulfill(body=f"<title>Visit {visits}</title><p>Content {visits}</p>")

        await page.route(site + "/subject", content)
        await page.goto(site + "/subject")
        await page.evaluate("sessionStorage.setItem('investigation', 'kept')")
        await page.context.add_cookies([{"name": "analysis", "value": "kept", "url": site}])
        state, tool, request, delivered = await observed(page)
        page_id = state.page_id
        request["params"]["wait_until"] = wait_until
        native, calls = page.reload, []

        async def counted(**kwargs):
            calls.append(kwargs)
            return await native(**kwargs)

        monkeypatch.setattr(page, "reload", counted)
        result = await tool.execute(request)
        assert result["status"] == "success" and result["error"] is None
        assert result["result"]["url"] == page.url == site + "/subject"
        assert result["result"]["reloaded"] is True and result["result"]["http_status"] == 200
        assert visits == 2 and len(calls) == 1 and calls[0]["wait_until"] == wait_until
        assert state.page is page and state.page_id == page_id and len(page.context.pages) == 1
        with pytest.raises(PageStateError, match="Refresh"):
            state.read()
        assert result["before_state_id"] == request["context"]["state_id"]
        assert result["after_state_id"] is None and result["observer_refs"] == {"l2": [], "l3": []}
        assert delivered and all(source is page for _, source in delivered)
        assert result["result"]["page_events"] == [event for event, _ in delivered]
        assert all(event["observed_during_action_id"] == request["action_id"] for event, _ in delivered)
        await page.wait_for_load_state("load")
        assert await page.title() == "Visit 2"
        assert await page.evaluate("sessionStorage.getItem('investigation')") == "kept"
        assert next(cookie for cookie in await page.context.cookies() if cookie["name"] == "analysis")["value"] == "kept"
        fresh = await state.refresh()
        assert fresh["page_id"] == page_id and fresh["state_id"] != request["context"]["state_id"]
        assert fresh["title"] == "Visit 2"
    asyncio.run(with_page(site, check))


def test_identical_html_is_a_new_document_and_old_element_cannot_be_clicked(site):
    async def check(page):
        html = '<title>Stable</title><button onclick="window.clicks = (window.clicks || 0) + 1">Inspect</button>'
        await page.route(site + "/same", lambda route: route.fulfill(body=html))
        await page.goto(site + "/same")
        await page.evaluate("window.previousDocument = true")
        state, tool, request, delivered = await observed(page)
        old = state.read()
        elements = ElementRegistry(state, timeout_ms=2000)
        found = await elements.query(visible_only=True, expected_state_id=old["state_id"])
        old_id = found["elements"][0]["element_id"]
        click = ClickTool(elements, timeout_ms=2000, page_events=tool.page_events)
        result = await tool.execute(request)
        assert result["result"]["reloaded"] is True
        assert await page.evaluate("window.previousDocument === undefined")
        stale = await click.execute(click_action(old_id, old["state_id"]))
        assert stale["error"]["code"] == "TARGET_STALE" and stale["result"]["clicked"] is False
        fresh = await state.refresh()
        assert fresh["url"] == old["url"] and fresh["dom_fingerprint"] == old["dom_fingerprint"]
        found = await elements.query(visible_only=True, expected_state_id=fresh["state_id"])
        new_id = found["elements"][0]["element_id"]
        assert new_id != old_id
        old_target = await click.execute(click_action(old_id, fresh["state_id"]))
        assert old_target["error"]["code"] == "ELEMENT_NOT_FOUND"
        accepted = await click.execute(click_action(new_id, fresh["state_id"]))
        assert accepted["result"]["clicked"] is True and await page.evaluate("window.clicks") == 1
    asyncio.run(with_page(site, check))


def test_redirect_and_http_error_are_returned_as_actual_reload_result(site):
    async def check(page):
        visits = 0

        async def content(route):
            nonlocal visits
            visits += 1
            if visits == 1:
                await route.fulfill(body="<title>Before redirect</title>")
            else:
                await route.fulfill(status=302, headers={"Location": site + "/missing"})

        await page.route(site + "/subject", content)
        await page.goto(site + "/subject")
        state, tool, request, delivered = await observed(page)
        result = await tool.execute(request)
        assert result["status"] == "success" and result["result"]["reloaded"] is True
        assert result["result"]["url"] == page.url == site + "/missing"
        assert result["result"]["http_status"] == 404 and visits == 2
    asyncio.run(with_page(site, check))


def test_reload_without_http_response_can_complete(site):
    async def check(page):
        assert page.url == "about:blank"
        await page.evaluate("window.previousDocument = true")
        state, tool, request, delivered = await observed(page)
        result = await tool.execute(request)
        assert result["status"] == "success" and result["result"]["reloaded"] is True
        assert result["result"]["http_status"] is None and result["result"]["url"] == "about:blank"
        assert await page.evaluate("window.previousDocument === undefined")
    asyncio.run(with_page(site, check))


def test_timeout_before_new_document_can_finish_later_without_mutating_returned_result(site, monkeypatch):
    async def check(page):
        visits, calls = 0, []
        release = asyncio.Event()

        async def content(route):
            nonlocal visits
            visits += 1
            if visits > 1:
                await release.wait()
            await route.fulfill(body=f"<title>Visit {visits}</title>")

        await page.route(site + "/subject", content)
        await page.goto(site + "/subject")
        state, tool, request, delivered = await observed(page, timeout_ms=400)
        native = page.reload

        async def counted(**kwargs):
            calls.append(kwargs)
            return await native(**kwargs)

        monkeypatch.setattr(page, "reload", counted)
        result = await tool.execute(request)
        saved_result = deepcopy(result)
        assert result["status"] == "timeout" and result["error"]["code"] == "NAVIGATION_TIMEOUT"
        assert result["result"]["reloaded"] is None and result["result"]["http_status"] is None
        # Edge may show a temporary Loading title while the response is withheld.
        assert await page.title() != "Visit 2" and visits == 2 and len(calls) == 1
        release.set()
        await page.wait_for_function("document.title === 'Visit 2'")
        await page.wait_for_load_state("load")
        assert delivered[-1][0]["observed_during_action_id"] is None
        assert delivered[-1][1] is page and result == saved_result and len(calls) == 1
        with pytest.raises(PageStateError):
            state.read()
        assert tool.page_events.begin("next") == []
        tool.page_events.end()
    asyncio.run(with_page(site, check))


def test_timeout_after_document_commit_is_not_completed_reload(site):
    async def check(page):
        visits = 0
        release = asyncio.Event()

        async def content(route):
            nonlocal visits
            visits += 1
            if visits == 1:
                await route.fulfill(body="<title>Before</title>")
            else:
                await route.fulfill(body='<title>After</title><p id="changed">New document</p><script src="/hold.js"></script>')

        async def script(route):
            await release.wait()
            await route.fulfill(content_type="application/javascript", body="window.scriptFinished = true")

        await page.route(site + "/subject", content)
        await page.route(site + "/hold.js", script)
        await page.goto(site + "/subject")
        state, tool, request, delivered = await observed(page, timeout_ms=400)
        result = await tool.execute(request)
        assert result["status"] == "timeout" and result["result"]["reloaded"] is None
        assert await page.title() == "After" and await page.locator("#changed").count() == 1
        assert await page.evaluate("document.readyState") == "loading"
        assert any(event["observed_during_action_id"] == request["action_id"] for event, _ in delivered)
        release.set()
        await page.wait_for_load_state("load")
        assert await page.evaluate("window.scriptFinished") is True and visits == 2
        with pytest.raises(PageStateError):
            state.read()
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("cancel", [False, True])
def test_timeout_or_cancel_after_native_completion_cleans_action_interval(site, monkeypatch, cancel):
    async def check(page):
        await page.goto(site + "/subject")
        state, tool, request, delivered = await observed(page, timeout_ms=400)
        native, completed, calls = page.reload, asyncio.Event(), []

        async def delayed_reply(**kwargs):
            calls.append(kwargs)
            await native(**kwargs)
            completed.set()
            await asyncio.Event().wait()

        monkeypatch.setattr(page, "reload", delayed_reply)
        task = asyncio.create_task(tool.execute(request))
        await asyncio.wait_for(completed.wait(), 3)
        if cancel:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            result = await task
            assert result["status"] == "timeout" and result["result"]["reloaded"] is None
        assert len(calls) == 1 and not page.is_closed()
        with pytest.raises(PageStateError):
            state.read()
        assert tool.page_events.begin("next") == []
        tool.page_events.end()
        await page.goto(site + "/later")
        assert delivered[-1][0]["observed_during_action_id"] is None
    asyncio.run(with_page(site, check))


def test_page_closed_during_pending_reload_is_not_success(site):
    async def check(page):
        await page.goto(site + "/subject")
        state, tool, request, delivered = await observed(page)
        received, release = asyncio.Event(), asyncio.Event()

        async def stalled(route):
            received.set()
            await release.wait()
            await route.abort()

        await page.route(site + "/subject", stalled)
        task = asyncio.create_task(tool.execute(request))
        await asyncio.wait_for(received.wait(), 3)
        await page.close()
        release.set()
        result = await task
        assert result["status"] == "failed" and result["error"]["code"] == "PAGE_CLOSED"
        assert result["result"]["reloaded"] is None and result["result"]["url"] is None
    asyncio.run(with_page(site, check))


def test_aborted_request_does_not_claim_the_page_closed(site):
    async def check(page):
        await page.goto(site + "/subject")
        state, tool, request, delivered = await observed(page)
        await page.route(site + "/subject", lambda route: route.abort("aborted"))
        result = await tool.execute(request)
        assert result["status"] == "failed" and result["result"]["reloaded"] is None
        assert result["error"]["code"] == "INTERNAL_ERROR" and not page.is_closed()
        with pytest.raises(PageStateError):
            state.read()
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("failure", ["wrong_state", "closed", "closed_events"])
def test_rejected_before_attempt_keeps_false_and_does_not_reload(site, monkeypatch, failure):
    async def check(page):
        await page.goto(site + "/subject")
        state, tool, request, delivered = await observed(page)
        original_state_id = state.read()["state_id"]

        async def unexpected(**kwargs):
            pytest.fail("A rejected request must not reload")

        monkeypatch.setattr(page, "reload", unexpected)
        if failure == "wrong_state":
            request["context"]["state_id"] = "old-state"
        elif failure == "closed":
            await page.close()
        else:
            tool.page_events.close()
        result = await tool.execute(request)
        expected = {"wrong_state": "TARGET_STALE", "closed": "PAGE_CLOSED", "closed_events": "INTERNAL_ERROR"}
        assert result["status"] == "failed" and result["error"]["code"] == expected[failure]
        assert result["result"]["reloaded"] is False
        if failure != "closed":
            assert state.read()["state_id"] == original_state_id
            assert page.url == site + "/subject"
    asyncio.run(with_page(site, check))


def test_delivery_failure_does_not_repeat_or_hide_completed_reload(site):
    async def check(page):
        await page.goto(site + "/subject")

        def failed_delivery(event, source):
            raise RuntimeError("controlled callback failure")

        state, tool, request, delivered = await observed(page, on_event=failed_delivery)
        result = await tool.execute(request)
        assert result["status"] == "success" and result["result"]["reloaded"] is True
        assert result["result"]["page_events"][0]["delivery_error"] == "PAGE_EVENT_DELIVERY_FAILED"
        assert tool.page_events.last_delivery_error is not None
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("change", [
    {"target": {"url": "https://example.invalid/"}},
    {"params": {"retry": True}}, {"params": {"wait_until": "ready"}},
])
def test_unapproved_targets_actions_and_wait_modes_are_rejected(change):
    request = action()
    request.update(change)
    with pytest.raises(ValidationError):
        ReloadInput.model_validate(request)


def test_configuration_and_default_wait_mode(site):
    assert ReloadInput.model_validate({**action(), "params": {}}).params.wait_until == "domcontentloaded"

    async def check(page):
        state, tool, request, delivered = await observed(page)
        for timeout_ms in (0, -1, True, 1.5):
            with pytest.raises(ValueError):
                ReloadTool(state, timeout_ms=timeout_ms, page_events=tool.page_events)
        other_state = PageState(page, timeout_ms=1000)
        with pytest.raises(ValueError):
            ReloadTool(other_state, timeout_ms=1000, page_events=tool.page_events)
    asyncio.run(with_page(site, check))


def test_sdk_delivers_actual_reload_result_to_next_manager_input(site):
    async def check(page):
        await page.goto(site + "/subject")
        page_state, tool, request, delivered = await observed(page)
        proof = await run_native_steps({"reload": tool}, [("reload", request)])
        assert proof.results[0]["result"]["reloaded"] is True
        assert proof.results[0]["result"]["url"] == page.url == site + "/subject"
        assert len(proof.actions) == 1
    asyncio.run(with_page(site, check))
