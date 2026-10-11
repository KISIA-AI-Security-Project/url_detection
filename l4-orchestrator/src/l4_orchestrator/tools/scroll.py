"""Scroll the assigned Page's document once; report observed coordinates only."""
import asyncio
from datetime import datetime, timezone
import inspect
from time import perf_counter
from typing import Callable, Literal

from playwright.async_api import Error, TimeoutError as BrowserTimeoutError
from pydantic import Field

from ..page_events import PageEvents
from ..page_state import PageState, PageStateError
from ..ports import Authorization, ExecutionPort
from ..schemas import WireModel
from .schemas import ActionContext, page_target_error


class ScrollParams(WireModel):
    direction: Literal["up", "down", "left", "right"]
    amount: float = Field(strict=True, gt=0, allow_inf_nan=False)


class ScrollInput(WireModel):
    action_id: str = Field(min_length=1)
    tool: Literal["scroll"]
    target: None
    params: ScrollParams
    context: ActionContext


_SCROLL = """(doc, delta) => {
    if (doc !== document) return null;
    const before = {x: window.scrollX, y: window.scrollY};
    window.scrollBy({left: delta.x, top: delta.y, behavior: 'instant'});
    return before;
}"""
_POSITION = """doc => doc === document ? {x: window.scrollX, y: window.scrollY} : null"""
_MESSAGES = {
    "TARGET_STALE": "The observed page or document changed. Observe again before deciding another action.",
    "BLOCKED_ACTION": "The caller did not reserve a scroll attempt. The document was not scrolled by this call.",
    "ACTION_TIMEOUT": "The scroll operation timed out. If attempted is true, scrolling may already have occurred; observe before deciding another action.",
    "PAGE_CLOSED": "The assigned Page is closed.",
    "BROWSER_CRASH": "The assigned Page crashed.",
    "INTERNAL_ERROR": "The scroll operation did not complete. No automatic retry was performed.",
}


class ScrollTool:
    def __init__(self, state: PageState, *, timeout_ms: int, wait_ms: int,
                 page_events: PageEvents, reserve_attempt: Callable[[dict], Authorization]):
        if type(timeout_ms) is not int or timeout_ms < 1:
            raise ValueError("timeout_ms must be a positive integer")
        if type(wait_ms) is not int or not 0 <= wait_ms < timeout_ms:
            raise ValueError("wait_ms must be a nonnegative integer smaller than timeout_ms")
        if page_events.state is not state:
            raise ValueError("Events must belong to the same PageState")
        if (not callable(reserve_attempt) or inspect.iscoroutinefunction(reserve_attempt)
                or inspect.iscoroutinefunction(getattr(reserve_attempt, "__call__", None))):
            raise TypeError("reserve_attempt must synchronously check and reserve one attempt")
        self.state = state
        self.timeout_ms = timeout_ms
        self.wait_ms = wait_ms
        self.page_events = page_events
        self.reserve_attempt = reserve_attempt

    async def execute(self, arguments):
        request = ScrollInput.model_validate(arguments)
        if error := page_target_error(request, self.state.page_id):
            return error
        state, page = self.state, self.state.page
        started_at = datetime.now(timezone.utc).isoformat()
        started = perf_counter()
        before_id, document, error = None, None, None
        attempted, moved = False, False
        status, events, listening = "success", [], False
        crashed, navigated = False, False
        coordinates = {"scroll_x": None, "scroll_y": None, "delta_x": None, "delta_y": None}

        def on_crash(*args):
            nonlocal crashed
            crashed = True

        def on_navigation(frame):
            nonlocal navigated
            if frame == page.main_frame:
                navigated = True

        def fail(code):
            nonlocal status, error
            if code == "STATE_CHANGED":
                code = "TARGET_STALE"
            if code not in _MESSAGES:
                code = "INTERNAL_ERROR"
            status = "timeout" if code == "ACTION_TIMEOUT" else "failed"
            error = {"code": code, "message": _MESSAGES[code],
                     "recoverable": code not in {"PAGE_CLOSED", "BROWSER_CRASH"}}

        try:
            async with asyncio.timeout(self.timeout_ms / 1000):
                before_id = state.read(request.context.state_id)["state_id"]
                document = await page.evaluate_handle("document")
                if not await document.evaluate("doc => doc === document"):
                    raise PageStateError("TARGET_STALE", _MESSAGES["TARGET_STALE"])
                state.read(before_id)
                events = self.page_events.begin(request.action_id)
                page.on("crash", on_crash)
                page.on("framenavigated", on_navigation)
                listening = True
                # The caller owns the investigation's count. Never refund uncertain attempts.
                permit = self.reserve_attempt(request.model_dump(mode="json"))
                if inspect.isawaitable(permit):
                    if inspect.iscoroutine(permit):
                        permit.close()
                    raise TypeError("reserve_attempt must return Authorization synchronously")
                if not isinstance(permit, Authorization) or type(permit.allowed) is not bool:
                    raise TypeError("reserve_attempt must return Authorization with a boolean allowed")
                if not permit.allowed:
                    raise PageStateError("BLOCKED_ACTION", _MESSAGES["BLOCKED_ACTION"])
                state.read(before_id)
                state.invalidate()  # Viewport movement need not mutate the DOM.
                attempted, moved = True, None
                amount = request.params.amount
                delta = {"x": 0, "y": 0}
                axis = "x" if request.params.direction in {"left", "right"} else "y"
                delta[axis] = -amount if request.params.direction in {"up", "left"} else amount
                before = await document.evaluate(_SCROLL, delta)
                if before is None:
                    raise PageStateError("TARGET_STALE", _MESSAGES["TARGET_STALE"])
                # This is a bounded observation delay, not a claim that lazy loading ended.
                await asyncio.sleep(self.wait_ms / 1000)
                after = await document.evaluate(_POSITION)
                if navigated or after is None:
                    raise PageStateError("TARGET_STALE", _MESSAGES["TARGET_STALE"])
                if page.is_closed() or crashed:
                    raise PageStateError("BROWSER_CRASH" if crashed else "PAGE_CLOSED", "Page unavailable")
                dx, dy = after["x"] - before["x"], after["y"] - before["y"]
                coordinates = {"scroll_x": after["x"], "scroll_y": after["y"],
                               "delta_x": dx, "delta_y": dy}
                moved = dx != 0 or dy != 0
        except (TimeoutError, BrowserTimeoutError):
            fail("ACTION_TIMEOUT")
        except PageStateError as exc:
            fail(exc.code)
        except Exception:
            fail("BROWSER_CRASH" if crashed else "PAGE_CLOSED" if page.is_closed()
                 else "TARGET_STALE" if navigated else "INTERNAL_ERROR")
        finally:
            if listening:
                self.page_events.end()
                page.remove_listener("crash", on_crash)
                page.remove_listener("framenavigated", on_navigation)
            if document is not None:
                try:
                    await document.dispose()
                except Error:
                    pass  # Navigation/closure may have already destroyed the document handle.

        return {
            "action_id": request.action_id, "tool": "scroll", "status": status,
            "started_at": started_at, "finished_at": datetime.now(timezone.utc).isoformat(),
            "duration_ms": round((perf_counter() - started) * 1000),
            "before_state_id": before_id, "after_state_id": None,
            "result": {"direction": request.params.direction, "amount": request.params.amount,
                       "attempted": attempted, "moved": moved, **coordinates,
                       "page_events": events, "event_scope": "scroll_call_interval"},
            "observer_refs": {"l2": [], "l3": []}, "error": error,
        }

    def as_port(self):
        def prepare(request, assigned_task):
            return ScrollInput.model_validate(request["arguments"]).model_dump(mode="json")

        return ExecutionPort(
            description="Scroll the assigned Page's whole document once in a requested direction. Returns measured coordinates and displacement, including zero movement at a boundary; does not read newly visible content.",
            kind="tool", provenance="new_observation",
            permission_description="Requires a valid PageState and a caller-owned attempt reservation. Only target:null is supported. Invalidates the old observation before attempting scroll; no automatic refresh, repeat, image capture or storage. Caller owns serial Page access, limits, observation delay and page events.",
            prepare=prepare, invoke=self.execute,
        )
