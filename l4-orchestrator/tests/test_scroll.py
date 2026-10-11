from sdk_tool_checks import run_native_steps
import asyncio
from copy import deepcopy

import pytest
from pydantic import ValidationError

playwright = pytest.importorskip("playwright.async_api", reason="Install the browser extra to run browser tests")

from l4_orchestrator.page_events import PageEvents
from l4_orchestrator.page_state import PageState, PageStateError
from l4_orchestrator.ports import Authorization
from l4_orchestrator.tools.scroll import ScrollInput, ScrollTool, _SCROLL
from test_navigate import site, with_page


HTML = '''<!doctype html><style>html {scroll-behavior:smooth} body {margin:0}
#document {width:5000px;height:5000px}
#box {position:fixed;top:20px;left:20px;width:200px;height:100px;overflow:auto}
</style><div id="document">Page</div><div id="box"><div style="height:600px;width:600px">Inner</div></div>'''


def action(state_id=None, direction="down", amount=600):
    return {"action_id": "scroll-check", "tool": "scroll", "target": None,
            "params": {"direction": direction, "amount": amount},
            "context": {"job_id": "local-check", "scenario_id": "scroll",
                        "step_id": "move", "state_id": state_id}}


async def observed(page, *, html=HTML, start=(0, 0), limit=1, timeout_ms=3000, wait_ms=60):
    await page.set_content(html)
    await page.evaluate("([x,y]) => window.scrollTo({left:x,top:y,behavior:'instant'})", start)
    await page.evaluate("() => new Promise(requestAnimationFrame)")
    state = PageState(page, timeout_ms=3000)
    snapshot = await state.refresh()
    reservations, events = [], []

    def reserve(request):
        reservations.append(request)
        return Authorization(len(reservations) <= limit, "Controlled investigation limit")

    page_events = PageEvents(state, on_event=lambda event, event_page: events.append((event, event_page)))
    tool = ScrollTool(state, timeout_ms=timeout_ms, wait_ms=wait_ms,
                      page_events=page_events, reserve_attempt=reserve)
    return state, tool, action(snapshot["state_id"]), reservations, events


@pytest.mark.parametrize("direction, dx, dy", [
    ("down", 0, 600), ("up", 0, -600), ("right", 600, 0), ("left", -600, 0),
])
def test_four_directions_whole_document_and_same_page(site, direction, dx, dy, monkeypatch):
    async def check(page):
        state, tool, request, reservations, events = await observed(page, start=(1000, 1000))
        request["params"]["direction"] = direction
        source = await page.content()
        await page.mouse.move(60, 60)  # Pointer lies over a separately scrollable fixed box.
        async def forbidden_refresh():
            pytest.fail("Scroll must not recollect PageState automatically")
        monkeypatch.setattr(state, "refresh", forbidden_refresh)
        result = await tool.execute(request)
        data = result["result"]
        assert result["status"] == "success" and result["error"] is None
        assert data["attempted"] is True and data["moved"] is True
        assert (data["scroll_x"], data["scroll_y"], data["delta_x"], data["delta_y"]) == (1000+dx, 1000+dy, dx, dy)
        assert data["amount"] == 600 and data["direction"] == direction
        assert await page.evaluate("[scrollX, scrollY]") == [1000+dx, 1000+dy]
        assert await page.locator("#box").evaluate("node => [node.scrollLeft, node.scrollTop]") == [0, 0]
        assert await page.content() == source and tool.state.page is page and events == []
        assert len(reservations) == 1 and reservations[0] == request
        assert result["before_state_id"] == request["context"]["state_id"]
        assert result["after_state_id"] is None and result["observer_refs"] == {"l2": [], "l3": []}
        with pytest.raises(PageStateError):
            state.read()
        stale = await tool.execute(request)
        assert stale["error"]["code"] == "TARGET_STALE" and stale["result"]["attempted"] is False
        assert len(reservations) == 1
    asyncio.run(with_page(site, check))


def test_partial_boundary_zero_movement_and_shared_limit(site):
    async def check(page):
        state, tool, request, reservations, events = await observed(page, limit=2)
        end = await page.evaluate("document.scrollingElement.scrollHeight - innerHeight")
        await page.evaluate("y => scrollTo({top:y,behavior:'instant'})", end - 80)
        request["context"]["state_id"] = (await state.refresh())["state_id"]
        partial = await tool.execute(request)
        assert partial["status"] == "success" and partial["result"]["amount"] == 600
        assert partial["result"]["delta_y"] == 80 and partial["result"]["scroll_y"] == end
        request["context"]["state_id"] = (await state.refresh())["state_id"]
        zero = await tool.execute(request)
        assert zero["status"] == "success" and zero["result"]["moved"] is False
        assert zero["result"]["attempted"] is True and zero["result"]["delta_y"] == 0
        before = await state.refresh()
        request["context"]["state_id"] = before["state_id"]
        request["params"]["direction"] = "up"
        # A second Tool uses the same caller-owned budget, not a fresh per-Tool count.
        other = ScrollTool(state, timeout_ms=3000, wait_ms=0, page_events=tool.page_events,
                           reserve_attempt=tool.reserve_attempt)
        blocked = await other.execute(request)
        assert blocked["error"]["code"] == "BLOCKED_ACTION" and blocked["result"]["attempted"] is False
        assert blocked["result"]["scroll_y"] is None and state.read() == before
        assert await page.evaluate("scrollY") == end and len(reservations) == 3
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("params", [
    {"direction": "diagonal", "amount": 600}, {"direction": "down", "amount": 0},
    {"direction": "down", "amount": -1}, {"direction": "down", "amount": True},
    {"direction": "down", "amount": "600"}, {"direction": "down", "amount": float("nan")},
    {"direction": "down", "amount": float("inf")}, {"direction": "down", "amount": 600, "repeat": 3},
])
def test_reject_invalid_inputs(params):
    request = action()
    request["params"] = params
    with pytest.raises(ValidationError):
        ScrollInput.model_validate(request)


def test_container_target_wrong_observation_and_closed_page_do_not_consume(site):
    async def check(page):
        state, tool, request, reservations, events = await observed(page)
        before = state.read()
        container = deepcopy(request)
        container["target"] = {"element_id": "box"}
        with pytest.raises(ValidationError):
            await tool.execute(container)
        assert state.read() == before and await page.evaluate("scrollY") == 0
        request["context"]["state_id"] = "another-state"
        result = await tool.execute(request)
        assert result["error"]["code"] == "TARGET_STALE" and result["result"]["attempted"] is False
        await page.close()
        result = await tool.execute(request)
        assert result["error"]["code"] == "PAGE_CLOSED" and result["result"]["attempted"] is False
        assert reservations == events == []
    asyncio.run(with_page(site, check))


def test_lazy_dom_change_is_not_a_navigation_or_automatic_refresh(site):
    async def check(page):
        state, tool, request, reservations, events = await observed(page, wait_ms=200)
        await page.evaluate('''() => addEventListener('scroll', () => setTimeout(() => {
            document.querySelector('#document').append('Lazy content');
        }, 40), {once:true})''')
        result = await tool.execute(request)
        assert result["status"] == "success" and result["result"]["delta_y"] == 600
        assert "Lazy content" in await page.locator("#document").inner_text()
        assert events == [] and len(reservations) == 1
        with pytest.raises(PageStateError):
            state.read()
    asyncio.run(with_page(site, check))


def test_scroll_snap_returns_measured_distance_not_requested_distance(site):
    async def check(page):
        html = '<!doctype html><style>html{scroll-snap-type:y mandatory}body{margin:0}section{height:500px;scroll-snap-align:start}</style>' + '<section>Snap</section>' * 8
        state, tool, request, reservations, events = await observed(page, html=html, wait_ms=100)
        request["params"]["amount"] = 400
        result = await tool.execute(request)
        assert result["status"] == "success" and result["result"]["amount"] == 400
        assert result["result"]["delta_y"] == await page.evaluate("scrollY") == 500
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("change", ["location.reload()", "location.href = destination", "location.hash = 'changed'"])
def test_navigation_including_same_url_cannot_mix_coordinates(site, change):
    async def check(page):
        await page.goto(site + "/source")
        state, tool, request, reservations, events = await observed(page, wait_ms=350)
        await page.evaluate("""({change, destination}) => addEventListener('scroll', () => {
            setTimeout(() => new Function('destination', change)(destination), 10);
        }, {once:true})""", {"change": change, "destination": site + "/destination"})
        result = await tool.execute(request)
        assert result["status"] == "failed" and result["error"]["code"] == "TARGET_STALE", result
        assert result["result"]["attempted"] is True and result["result"]["moved"] is None
        assert all(result["result"][key] is None for key in ("scroll_x", "scroll_y", "delta_x", "delta_y"))
        assert len(reservations) == 1 and len(events) == 1
        assert result["result"]["page_events"] == [events[0][0]]
        await page.goto(site + "/after-call")
        assert events[-1][0]["observed_during_action_id"] is None
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("cancel", [False, True])
def test_timeout_or_cancellation_after_actual_scroll_keeps_one_attempt_and_cleans_up(site, monkeypatch, cancel):
    async def check(page):
        state, tool, request, reservations, events = await observed(page, timeout_ms=400)
        completed_scroll = asyncio.Event()
        original = playwright.JSHandle.evaluate

        async def delayed_reply(handle, expression, arg=None):
            result = await original(handle, expression, arg)
            if expression == _SCROLL:
                completed_scroll.set()
                await asyncio.sleep(5)  # Simulate loss/delay of the response after actual movement.
            return result

        monkeypatch.setattr(playwright.JSHandle, "evaluate", delayed_reply)
        task = asyncio.create_task(tool.execute(request))
        await asyncio.wait_for(completed_scroll.wait(), 3)
        if cancel:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            result = await task
            assert result["status"] == "timeout" and result["result"]["attempted"] is True
            assert result["result"]["moved"] is None and result["result"]["delta_y"] is None
        assert await page.evaluate("scrollY") == 600 and len(reservations) == 1
        with pytest.raises(PageStateError):
            state.read()
        # end() ran on both timeout and cancellation. The persistent connection remains usable.
        assert tool.page_events.begin("next-call") == []
        tool.page_events.end()
        await page.goto(site + "/later")
        assert events[-1][0]["observed_during_action_id"] is None
    asyncio.run(with_page(site, check))


def test_close_during_observation_delay_does_not_claim_movement(site):
    async def check(page):
        state, tool, request, reservations, events = await observed(page, wait_ms=300)
        scrolled = asyncio.Event()
        await page.expose_function("reportScroll", lambda: scrolled.set())
        await page.evaluate("() => addEventListener('scroll', () => window.reportScroll(), {once:true})")
        task = asyncio.create_task(tool.execute(request))
        await asyncio.wait_for(scrolled.wait(), 3)
        await page.close()
        result = await task
        assert result["error"]["code"] == "PAGE_CLOSED" and result["result"]["moved"] is None
        assert len(reservations) == 1
    asyncio.run(with_page(site, check))


def test_budget_callback_failure_does_not_invalidate_or_move(site):
    async def check(page):
        state, tool, request, reservations, events = await observed(page)
        before = state.read()
        def failed_reservation(request):
            raise RuntimeError("caller failure")
        tool.reserve_attempt = failed_reservation
        result = await tool.execute(request)
        assert result["error"]["code"] == "INTERNAL_ERROR" and result["result"]["attempted"] is False
        assert state.read() == before and await page.evaluate("scrollY") == 0
        assert tool.page_events.begin("next") == []
        tool.page_events.end()
    asyncio.run(with_page(site, check))


def test_configuration_validation(site):
    async def check(page):
        state, tool, request, reservations, events = await observed(page)
        base = dict(timeout_ms=1000, wait_ms=50, page_events=tool.page_events, reserve_attempt=tool.reserve_attempt)
        for changed in ({"timeout_ms": 0}, {"wait_ms": -1}, {"wait_ms": 1000}, {"wait_ms": True}):
            with pytest.raises(ValueError):
                ScrollTool(state, **(base | changed))
        async def async_reservation(request):
            return Authorization(True, "invalid async callback")
        with pytest.raises(TypeError):
            ScrollTool(state, **(base | {"reserve_attempt": async_reservation}))
        other = PageState(page, timeout_ms=1000)
        with pytest.raises(ValueError):
            ScrollTool(other, **base)
    asyncio.run(with_page(site, check))


def test_sdk_receives_actual_scroll_result(site):
    async def check(page):
        state, tool, request, reservations, events = await observed(page)
        proof = await run_native_steps({"scroll": tool}, [("scroll", request)])
        assert proof.results[0]["result"]["delta_y"] == 600 and await page.evaluate("scrollY") == 600
        assert len(reservations) == len(proof.actions) == 1
    asyncio.run(with_page(site, check))
