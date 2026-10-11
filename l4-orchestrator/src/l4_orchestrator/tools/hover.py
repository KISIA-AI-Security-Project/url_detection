"""Move the pointer onto one observed element without scrolling or clicking."""
import asyncio
from datetime import datetime, timezone
from time import perf_counter
from typing import Literal

from playwright.async_api import Error, TimeoutError as BrowserTimeoutError
from pydantic import Field

from ..elements import ElementRegistry
from ..page_events import PageEvents
from ..page_state import PageStateError
from ..ports import ExecutionPort
from ..schemas import WireModel
from .schemas import ActionContext, page_target_error


class HoverTarget(WireModel):
    element_id: str = Field(min_length=1)


class HoverParams(WireModel):
    pass


class HoverInput(WireModel):
    action_id: str = Field(min_length=1)
    tool: Literal["hover"]
    target: HoverTarget
    params: HoverParams
    context: ActionContext


_CHECK = """node => {
    const box = node.getBoundingClientRect();
    return {
        connected: node.isConnected && node.getRootNode() === document,
        in_viewport: box.width > 0 && box.height > 0 && box.bottom > 0 && box.right > 0 &&
                     box.top < innerHeight && box.left < innerWidth
    };
}"""
_MESSAGES = {
    "TARGET_STALE": "The observed state or element is no longer current. Observe again before deciding another action.",
    "ELEMENT_NOT_FOUND": "The element ID is absent from the latest successful element query.",
    "ELEMENT_NOT_VISIBLE": "The observed element is hidden or outside the current viewport. Hover does not scroll it into view.",
    "ACTION_TIMEOUT": "The hover operation timed out. If hovered is null, pointer movement may already have occurred; observe before deciding another action.",
    "PAGE_CLOSED": "The assigned Page is closed.",
    "BROWSER_CRASH": "The assigned Page crashed.",
    "INTERNAL_ERROR": "The hover operation did not complete. No automatic retry was performed.",
}


class HoverTool:
    def __init__(self, elements: ElementRegistry, *, timeout_ms: int, page_events: PageEvents):
        if type(timeout_ms) is not int or timeout_ms < 1:
            raise ValueError("timeout_ms must be a positive integer")
        if page_events.state is not elements.state:
            raise ValueError("Elements and events must belong to the same PageState")
        self.elements = elements
        self.timeout_ms = timeout_ms
        self.page_events = page_events

    async def execute(self, arguments):
        request = HoverInput.model_validate(arguments)
        if error := page_target_error(request, self.elements.state.page_id):
            return error
        page, state = self.elements.page, self.elements.state
        started_at = datetime.now(timezone.utc).isoformat()
        started = perf_counter()
        before_id, node, error = None, None, None
        hovered = False  # None after starting an attempt until completion is confirmed.
        status, events, listening, crashed = "success", [], False, False

        def on_crash(*args):
            nonlocal crashed
            crashed = True

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
                node = await self.elements.resolve(request.target.element_id, expected_state_id=before_id)
                checks = await node.evaluate(_CHECK)
                if not checks["connected"]:
                    raise PageStateError("TARGET_STALE", _MESSAGES["TARGET_STALE"])
                if not checks["in_viewport"] or not await node.is_visible():
                    raise PageStateError("ELEMENT_NOT_VISIBLE", _MESSAGES["ELEMENT_NOT_VISIBLE"])
                # Disabled controls may still reveal hover descriptions; no enabled check.
                state.read(before_id)
                events = self.page_events.begin(request.action_id)
                page.on("crash", on_crash)
                listening = True
                state.invalidate()  # CSS :hover can change the view without a DOM mutation.
                hovered = None
                remaining_ms = max(1, self.timeout_ms - (perf_counter() - started) * 1000)
                await node.hover(force=False, scroll="none", timeout=remaining_ms)
                hovered = True
        except (TimeoutError, BrowserTimeoutError):
            fail("ACTION_TIMEOUT")
        except PageStateError as exc:
            fail(exc.code)
        except Error:
            code = "BROWSER_CRASH" if crashed else "PAGE_CLOSED" if page.is_closed() else "INTERNAL_ERROR"
            if code == "INTERNAL_ERROR" and node is not None:
                try:
                    async with asyncio.timeout(self.timeout_ms / 1000):
                        if not await node.evaluate("node => node.isConnected && node.getRootNode() === document"):
                            code = "TARGET_STALE"
                except (Error, TimeoutError):
                    pass
            fail(code)
        finally:
            if listening:
                self.page_events.end()
                page.remove_listener("crash", on_crash)
            if node is not None:
                try:
                    await node.dispose()
                except Error:
                    pass

        return {
            "action_id": request.action_id, "tool": "hover", "status": status,
            "started_at": started_at, "finished_at": datetime.now(timezone.utc).isoformat(),
            "duration_ms": round((perf_counter() - started) * 1000),
            "before_state_id": before_id, "after_state_id": None,
            "result": {"element_id": request.target.element_id, "hovered": hovered,
                       "page_events": events, "event_scope": "hover_call_interval"},
            "observer_refs": {"l2": [], "l3": []}, "error": error,
        }

    def as_port(self):
        def prepare(request, assigned_task):
            return HoverInput.model_validate(request["arguments"]).model_dump(mode="json")

        return ExecutionPort(
            description="Move the pointer onto the exact previously observed element in the current viewport. Returns hover action completion, not confirmation that a menu or tooltip appeared. Leaves the pointer in place for subsequent observation or click.",
            kind="tool", provenance="new_observation",
            permission_description="Uses the assigned Page and element registry. Checks current identity and visibility; no enabled requirement, force, automatic scroll, click, refresh, retry or storage. Invalidates PageState before the attempt. Caller owns serial Page access and follow-up observation.",
            prepare=prepare, invoke=self.execute,
        )
