"""Click one previously observed node. The caller owns Page lifetime and follow-up."""
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


class ClickTarget(WireModel):
    element_id: str = Field(min_length=1)


class ClickParams(WireModel):
    pass


class ClickInput(WireModel):
    action_id: str = Field(min_length=1)
    tool: Literal["click"]
    target: ClickTarget
    params: ClickParams
    context: ActionContext


_CHECK = """node => {
    const owner = node.closest('[aria-disabled="true" i],[aria-disabled="false" i]');
    return {
        connected: node.isConnected && node.getRootNode() === document,
        enabled: !node.matches(':disabled') && !node.closest('[inert]') &&
                 owner?.getAttribute('aria-disabled').toLowerCase() !== 'true'
    };
}"""


class ClickTool:
    def __init__(self, elements: ElementRegistry, *, timeout_ms: int,
                 page_events: PageEvents):
        if type(timeout_ms) is not int or timeout_ms < 1:
            raise ValueError("timeout_ms must be a positive integer")
        if page_events.state is not elements.state:
            raise ValueError("Elements and events must belong to the same PageState")
        self.elements = elements
        self.timeout_ms = timeout_ms
        self.page_events = page_events

    async def execute(self, arguments):
        request = ClickInput.model_validate(arguments)
        if error := page_target_error(request, self.elements.state.page_id):
            return error
        page, state = self.elements.page, self.elements.state
        started_at = datetime.now(timezone.utc).isoformat()
        started = perf_counter()
        before_id, node, error = None, None, None
        clicked = False  # False before calling click; None if its completion is unknown.
        status = "success"
        events = []
        listening = False
        crashed = False

        def on_crash(*args):
            nonlocal crashed
            crashed = True

        def fail(code, message):
            nonlocal error, status
            status = "timeout" if code == "ACTION_TIMEOUT" else "failed"
            error = {"code": code, "message": message,
                     "recoverable": code not in {"PAGE_CLOSED", "BROWSER_CRASH"}}

        try:
            async with asyncio.timeout(self.timeout_ms / 1000):
                snapshot = state.read(request.context.state_id)
                before_id = snapshot["state_id"]
                node = await self.elements.resolve(request.target.element_id, expected_state_id=before_id)
                checks = await node.evaluate(_CHECK)
                if not checks["connected"]:
                    raise PageStateError("TARGET_STALE", "The observed node was removed or replaced.")
                if not await node.is_visible():
                    raise PageStateError("ELEMENT_NOT_VISIBLE", "The observed element is not visible.")
                if not checks["enabled"] or not await node.is_enabled():
                    raise PageStateError("ELEMENT_DISABLED", "The observed element is disabled or inert.")
                state.read(before_id)
                events = self.page_events.begin(request.action_id)
                page.on("crash", on_crash)
                listening = True
                # Do this only AFTER resolve/preconditions, immediately before attempting input.
                # Focus/check-state/scroll effects need not emit a DOM mutation notification.
                state.invalidate()
                clicked = None
                remaining_ms = max(1, self.timeout_ms - (perf_counter() - started) * 1000)
                await node.click(button="left", click_count=1, force=False, timeout=remaining_ms)
                clicked = True
        except (TimeoutError, BrowserTimeoutError):
            fail("ACTION_TIMEOUT", "The click operation timed out. If clicked is null, input may already have occurred; observe before deciding another action.")
        except PageStateError as exc:
            fail("TARGET_STALE" if exc.code == "STATE_CHANGED" else exc.code, str(exc))
        except Error:
            code = "BROWSER_CRASH" if crashed else "PAGE_CLOSED" if page.is_closed() else "INTERNAL_ERROR"
            if code == "INTERNAL_ERROR" and node is not None:
                try:
                    async with asyncio.timeout(self.timeout_ms / 1000):
                        if not await node.evaluate("node => node.isConnected && node.getRootNode() === document"):
                            code = "TARGET_STALE"
                except (Error, TimeoutError):
                    pass
            fail(code, "The click operation did not complete. No automatic retry was performed.")
        finally:
            if listening:
                self.page_events.end()
                page.remove_listener("crash", on_crash)
            if node is not None:
                try:
                    await node.dispose()
                except Error:
                    pass  # A closed/navigated page may already have released its handles.

        return {
            "action_id": request.action_id, "tool": "click", "status": status,
            "started_at": started_at, "finished_at": datetime.now(timezone.utc).isoformat(),
            "duration_ms": round((perf_counter() - started) * 1000),
            "before_state_id": before_id, "after_state_id": None,
            "result": {"element_id": request.target.element_id, "clicked": clicked,
                       "page_events": events, "event_scope": "click_call_interval"},
            "observer_refs": {"l2": [], "l3": []}, "error": error,
        }

    def as_port(self):
        def prepare(request, assigned_task):
            return ClickInput.model_validate(request["arguments"]).model_dump(mode="json")

        return ExecutionPort(
            description="Click the exact node from the assigned Page's latest successful element query once. Returns completion and page events observed during this call; does not judge the application's outcome or capture another image.",
            kind="tool", provenance="new_observation",
            permission_description="Checks observed identity, visibility and enabled state; uses a normal left click without force or selector fallback. Invalidates prior PageState before the attempt. The caller owns serial access, network policy, popup handling and later refresh. No automatic retry or storage.",
            prepare=prepare, invoke=self.execute,
        )
