from sdk_tool_checks import run_native_steps
import asyncio
from copy import deepcopy

import pytest
from pydantic import ValidationError

pytest.importorskip("playwright.async_api")

from l4_orchestrator.page_events import PageEvents
from l4_orchestrator.page_state import PageState, PageStateError
from l4_orchestrator.ports import Authorization
from l4_orchestrator.tools.go_back import GoBackInput, GoBackTool
from test_navigate import site, with_page


def action(state_id=None, wait_until="domcontentloaded"):
    return {"action_id": "back-check", "tool": "go_back", "target": None,
            "params": {"wait_until": wait_until},
            "context": {"job_id": "local-check", "scenario_id": "history",
                        "step_id": "return-to-list", "state_id": state_id}}


async def observed(page, *, timeout_ms=3000):
    await page.evaluate("() => new Promise(requestAnimationFrame)")
    state = PageState(page, timeout_ms=2000)
    snapshot = await state.refresh()
    delivered = []
    events = PageEvents(state, on_event=lambda event, source: delivered.append((event, source)))
    tool = GoBackTool(state, timeout_ms=timeout_ms, page_events=events)
    return state, tool, action(snapshot["state_id"]), delivered


async def history(page):
    session = await page.context.new_cdp_session(page)
    try:
        return await session.send("Page.getNavigationHistory")
    finally:
        await session.detach()


async def reset_history(page):
    session = await page.context.new_cdp_session(page)
    try:
        await session.send("Page.resetNavigationHistory")
    finally:
        await session.detach()


@pytest.mark.parametrize("wait_until", ["commit", "domcontentloaded", "load", "networkidle"])
def test_one_native_step_reuses_page_and_invalidates_observation(site, wait_until):
    async def check(page):
        await page.goto(site + "/earlier")
        await page.goto(site + "/list")
        await page.goto(site + "/detail")
        await page.evaluate("sessionStorage.setItem('investigation', 'kept')")
        state, tool, request, delivered = await observed(page)
        request["params"]["wait_until"] = wait_until
        page_id = state.page_id
        result = await tool.execute(request)
        assert result["status"] == "success" and result["error"] is None
        assert result["result"]["previous_url"] == site + "/detail"
        assert result["result"]["current_url"] == page.url == site + "/list"
        assert result["result"]["moved"] is True and result["result"]["attempted"] is True
        assert result["result"]["http_status"] == 200
        assert state.page is page and state.page_id == page_id and len(page.context.pages) == 1
        assert await page.evaluate("sessionStorage.getItem('investigation')") == "kept"
        with pytest.raises(PageStateError, match="Refresh"):
            state.read()
        assert result["before_state_id"] == request["context"]["state_id"]
        assert result["after_state_id"] is None and result["observer_refs"] == {"l2": [], "l3": []}
        assert delivered and all(source is page for _, source in delivered)
        assert result["result"]["page_events"] == [event for event, _ in delivered]
        assert all(event["observed_during_action_id"] == request["action_id"] for event, _ in delivered)
        # A new explicit observation is available on the same state owner.
        await page.wait_for_load_state("load")
        fresh = await state.refresh()
        assert fresh["page_id"] == page_id and fresh["state_id"] != request["context"]["state_id"]
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("forward_entries", [False, True])
def test_no_previous_entry_including_forward_history_does_not_attempt(site, forward_entries, monkeypatch):
    async def check(page):
        await page.goto(site + "/first")
        await reset_history(page)
        if forward_entries:
            await page.goto(site + "/second")
            await page.go_back()
        actual_history = await history(page)
        assert actual_history["currentIndex"] == 0
        assert len(actual_history["entries"]) == (2 if forward_entries else 1)
        state, tool, request, delivered = await observed(page)

        async def unexpected(**kwargs):
            pytest.fail("No native back call is needed when the browser has no previous entry")

        monkeypatch.setattr(page, "go_back", unexpected)
        result = await tool.execute(request)
        assert result["status"] == "no_effect" and result["error"] is None
        assert result["result"]["attempted"] is False and result["result"]["moved"] is False
        assert result["result"]["previous_url"] == result["result"]["current_url"] == site + "/first"
        assert delivered == [] and state.read()["state_id"] == request["context"]["state_id"]
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("kind", ["same_url", "push_path", "hash"])
def test_same_document_history_is_real_movement_without_http_response(site, kind):
    async def check(page):
        await page.goto(site + "/spa")
        await page.evaluate("history.replaceState({step: 1}, '', location.href)")
        if kind == "same_url":
            await page.evaluate("history.pushState({step: 2}, '', location.href)")
        elif kind == "push_path":
            await page.evaluate("history.pushState({step: 2}, '', '/spa/detail')")
        else:
            await page.evaluate("location.hash = 'detail'")
        before_url = page.url
        state, tool, request, delivered = await observed(page)
        result = await tool.execute(request)
        assert result["status"] == "success" and result["result"]["moved"] is True
        assert result["result"]["http_status"] is None
        assert result["result"]["previous_url"] == before_url
        assert result["result"]["current_url"] == site + "/spa"
        assert await page.evaluate("history.state.step") == 1
        assert any(event["kind"] == "navigation" for event, _ in delivered)
        with pytest.raises(PageStateError):
            state.read()
    asyncio.run(with_page(site, check))


def test_back_uses_real_redirect_destination_and_http_error_is_a_loaded_page(site):
    async def check(page):
        visits = 0

        async def destination(route):
            nonlocal visits
            visits += 1
            if visits == 1:
                await route.fulfill(body="<title>Original listing</title>")
            else:
                await route.fulfill(status=302, headers={"Location": site + "/missing"})

        await page.route(site + "/list", destination)
        await page.goto(site + "/list")
        await page.goto(site + "/detail")
        state, tool, request, delivered = await observed(page)
        result = await tool.execute(request)
        assert result["status"] == "success" and result["result"]["moved"] is True
        assert visits == 2 and result["result"]["previous_url"] == site + "/detail"
        assert result["result"]["current_url"] == page.url == site + "/missing"
        assert result["result"]["http_status"] == 404
    asyncio.run(with_page(site, check))


def test_timeout_before_commit_can_complete_later_without_retry_or_old_action_id(site, monkeypatch):
    async def check(page):
        visits, calls = 0, []
        release = asyncio.Event()

        async def destination(route):
            nonlocal visits
            visits += 1
            if visits > 1:
                await release.wait()
            await route.fulfill(body="<title>Back target</title>")

        await page.route(site + "/list", destination)
        await page.goto(site + "/list")
        await page.goto(site + "/detail")
        state, tool, request, delivered = await observed(page, timeout_ms=400)
        native = page.go_back

        async def counted(**kwargs):
            calls.append(kwargs)
            return await native(**kwargs)

        monkeypatch.setattr(page, "go_back", counted)
        result = await tool.execute(request)
        frozen_result = deepcopy(result)
        assert result["status"] == "timeout" and result["error"]["code"] == "NAVIGATION_TIMEOUT"
        assert result["result"]["moved"] is None and result["result"]["attempted"] is True
        assert result["result"]["current_url"] == site + "/detail"
        assert visits == 2 and len(calls) == 1
        release.set()
        await page.wait_for_url(site + "/list", wait_until="load")
        assert delivered[-1][0]["observed_during_action_id"] is None
        assert delivered[-1][1] is page and result == frozen_result
        assert len(calls) == 1 and not page.is_closed()
        with pytest.raises(PageStateError):
            state.read()
        assert tool.page_events.begin("next") == []
        tool.page_events.end()
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("cancel", [False, True])
def test_timeout_or_cancel_after_actual_back_keeps_uncertainty_and_cleans_up(site, monkeypatch, cancel):
    async def check(page):
        await page.goto(site + "/earlier")
        await page.goto(site + "/list")
        await page.goto(site + "/detail")
        state, tool, request, delivered = await observed(page, timeout_ms=400)
        native, open_session = page.go_back, page.context.new_cdp_session
        moved, calls, sessions = asyncio.Event(), [], []

        async def capture_session(target):
            session = await open_session(target)
            sessions.append(session)
            return session

        async def delayed_reply(**kwargs):
            calls.append(kwargs)
            await native(**kwargs)
            moved.set()
            await asyncio.Event().wait()

        monkeypatch.setattr(page.context, "new_cdp_session", capture_session)
        monkeypatch.setattr(page, "go_back", delayed_reply)
        task = asyncio.create_task(tool.execute(request))
        await asyncio.wait_for(moved.wait(), 3)
        if cancel:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            result = await task
            assert result["status"] == "timeout" and result["result"]["moved"] is None
            assert result["result"]["current_url"] == site + "/list"
        assert page.url == site + "/list" and len(calls) == 1
        assert len(sessions) == 1
        with pytest.raises(Exception, match="closed"):
            await sessions[0].send("Page.getNavigationHistory")
        with pytest.raises(PageStateError):
            state.read()
        assert tool.page_events.begin("next") == []
        tool.page_events.end()
        await page.goto(site + "/late")
        assert delivered[-1][0]["observed_during_action_id"] is None
    asyncio.run(with_page(site, check))


def test_history_changed_between_check_and_action_is_not_called_no_effect(site, monkeypatch):
    async def check(page):
        await page.goto(site + "/list")
        await page.goto(site + "/detail")
        state, tool, request, delivered = await observed(page)
        native = page.go_back

        async def changed_history(**kwargs):
            await page.evaluate("history.pushState({raced: true}, '', location.href)")
            return await native(**kwargs)

        monkeypatch.setattr(page, "go_back", changed_history)
        result = await tool.execute(request)
        assert result["status"] == "failed"
        assert result["error"]["code"] == "HISTORY_MOVEMENT_UNCONFIRMED"
        assert result["result"]["moved"] is None and result["result"]["attempted"] is True
        assert result["result"]["previous_url"] == result["result"]["current_url"] == site + "/detail"
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("cancel", [False, True])
def test_late_session_creation_is_released_after_timeout_or_cancel(site, monkeypatch, cancel):
    async def check(page):
        await page.goto(site + "/list")
        await page.goto(site + "/detail")
        state, tool, request, delivered = await observed(page, timeout_ms=150)
        native_open = page.context.new_cdp_session
        created, release, detached = asyncio.Event(), asyncio.Event(), asyncio.Event()
        sessions = []

        async def delayed_open(target):
            session = await native_open(target)
            sessions.append(session)
            native_detach = session.detach

            async def counted_detach():
                await native_detach()
                detached.set()

            monkeypatch.setattr(session, "detach", counted_detach)
            created.set()
            await release.wait()
            return session

        monkeypatch.setattr(page.context, "new_cdp_session", delayed_open)
        task = asyncio.create_task(tool.execute(request))
        await asyncio.wait_for(created.wait(), 3)
        if cancel:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            result = await task
            assert result["status"] == "timeout" and result["result"]["attempted"] is False
        # The tool returned before the creation reply; it still owns the late connection.
        assert not detached.is_set() and page.url == site + "/detail"
        assert state.read()["state_id"] == request["context"]["state_id"]
        assert tool.page_events.begin("next") == []
        tool.page_events.end()
        release.set()
        await asyncio.wait_for(detached.wait(), 3)
        with pytest.raises(Exception, match="closed"):
            await sessions[0].send("Page.getNavigationHistory")
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("failure", ["wrong_state", "closed", "closed_events"])
def test_rejected_before_attempt_does_not_navigate(site, failure):
    async def check(page):
        await page.goto(site + "/list")
        await page.goto(site + "/detail")
        state, tool, request, delivered = await observed(page)
        if failure == "wrong_state":
            request["context"]["state_id"] = "old-observation"
        elif failure == "closed":
            await page.close()
        else:
            tool.page_events.close()
        result = await tool.execute(request)
        expected = {"wrong_state": "TARGET_STALE", "closed": "PAGE_CLOSED", "closed_events": "INTERNAL_ERROR"}
        assert result["status"] == "failed" and result["error"]["code"] == expected[failure]
        assert result["result"]["attempted"] is False and result["result"]["moved"] is False
        assert result["result"]["current_url"] == (None if failure == "closed" else site + "/detail")
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("change", [
    {"target": {"url": "https://example.invalid/"}},
    {"params": {"steps": 2}}, {"params": {"wait_until": "ready"}},
])
def test_extra_targets_steps_and_unknown_wait_mode_are_rejected(change):
    request = action()
    request.update(change)
    with pytest.raises(ValidationError):
        GoBackInput.model_validate(request)


def test_configuration_and_default_wait_mode(site):
    assert GoBackInput.model_validate({**action(), "params": {}}).params.wait_until == "domcontentloaded"

    async def check(page):
        state, tool, request, delivered = await observed(page)
        for timeout_ms in (0, -1, True, 1.5):
            with pytest.raises(ValueError):
                GoBackTool(state, timeout_ms=timeout_ms, page_events=tool.page_events)
        other_state = PageState(page, timeout_ms=1000)
        with pytest.raises(ValueError):
            GoBackTool(other_state, timeout_ms=1000, page_events=tool.page_events)
    asyncio.run(with_page(site, check))


def test_sdk_delivers_the_actual_history_result(site):
    async def check(page):
        await page.goto(site + "/list")
        await page.goto(site + "/detail")
        page_state, tool, request, delivered = await observed(page)
        proof = await run_native_steps({"go_back": tool}, [("go_back", request)])
        assert proof.results[0]["result"]["moved"] is True
        assert proof.results[0]["result"]["current_url"] == page.url == site + "/list"
        assert len(proof.actions) == 1
    asyncio.run(with_page(site, check))
