"""Reload the caller's existing Page once; observation is a separate step."""
import asyncio
from datetime import datetime, timezone
from time import perf_counter
from typing import Literal

from playwright.async_api import Error, TimeoutError as BrowserTimeoutError
from pydantic import Field

from ..page_events import PageEvents
from ..page_state import PageState, PageStateError
from ..ports import ExecutionPort
from ..schemas import WireModel
from .schemas import ActionContext, page_target_error


class ReloadParams(WireModel):
    wait_until: Literal["commit", "domcontentloaded", "load", "networkidle"] = "domcontentloaded"


class ReloadInput(WireModel):
    action_id: str = Field(min_length=1)
    tool: Literal["reload"]
    target: None
    params: ReloadParams
    context: ActionContext


_MESSAGES = {
    "TARGET_STALE": "The requested observation is no longer current. Observe before deciding another action.",
    "NAVIGATION_TIMEOUT": "Reload timed out. It may complete later; observe before deciding another action. No automatic retry was performed.",
    "PAGE_CLOSED": "The assigned Page is closed.",
    "BROWSER_CRASH": "The assigned Page crashed.",
    "INTERNAL_ERROR": "Reload could not be completed. No automatic retry was performed.",
}


class ReloadTool:
    def __init__(self, state: PageState, *, timeout_ms: int, page_events: PageEvents):
        if type(timeout_ms) is not int or timeout_ms < 1:
            raise ValueError("timeout_ms must be a positive integer")
        if page_events.state is not state:
            raise ValueError("State and events must belong to the same PageState")
        self.state = state
        self.timeout_ms = timeout_ms
        self.page_events = page_events

    async def execute(self, arguments):
        request = ReloadInput.model_validate(arguments)
        if error := page_target_error(request, self.state.page_id):
            return error
        state, page = self.state, self.state.page
        started_at = datetime.now(timezone.utc).isoformat()
        started = perf_counter()
        before_id, http_status, error = None, None, None
        status, reloaded = "success", False
        events, listening, crashed = [], False, False

        def on_crash(*args):
            nonlocal crashed
            crashed = True

        def fail(code):
            nonlocal status, error
            if code == "STATE_CHANGED":
                code = "TARGET_STALE"
            if code not in _MESSAGES:
                code = "INTERNAL_ERROR"
            status = "timeout" if code == "NAVIGATION_TIMEOUT" else "failed"
            error = {"code": code, "message": _MESSAGES[code],
                     "recoverable": code not in {"PAGE_CLOSED", "BROWSER_CRASH"}}

        try:
            async with asyncio.timeout(self.timeout_ms / 1000):
                before_id = state.read(request.context.state_id)["state_id"]
                events = self.page_events.begin(request.action_id)
                page.on("crash", on_crash)
                listening = True
                # Even the same URL and HTML can produce a new document and new elements.
                state.invalidate()
                reloaded = None
                remaining_ms = max(1, self.timeout_ms - (perf_counter() - started) * 1000)
                response = await page.reload(wait_until=request.params.wait_until, timeout=remaining_ms)
                reloaded = True  # Native reload reached wait_until; not a content/risk judgment.
                http_status = response.status if response is not None else None
        except (TimeoutError, BrowserTimeoutError):
            fail("NAVIGATION_TIMEOUT")
        except PageStateError as exc:
            fail(exc.code)
        except Error:
            # Navigation can report an abort before the Page's close/crash event arrives.
            # One bounded, read-only liveness check lets us use observed lifecycle state;
            # an aborted request alone is not proof that the Page closed.
            if not crashed and not page.is_closed():
                remaining = self.timeout_ms / 1000 - (perf_counter() - started)
                if remaining > 0:
                    try:
                        async with asyncio.timeout(remaining):
                            await page.evaluate("() => true")
                    except (Error, TimeoutError):
                        pass
            fail("BROWSER_CRASH" if crashed else "PAGE_CLOSED" if page.is_closed() else "INTERNAL_ERROR")
        finally:
            if listening:
                self.page_events.end()
                page.remove_listener("crash", on_crash)

        return {
            "action_id": request.action_id, "tool": "reload", "status": status,
            "started_at": started_at, "finished_at": datetime.now(timezone.utc).isoformat(),
            "duration_ms": round((perf_counter() - started) * 1000),
            "before_state_id": before_id, "after_state_id": None,
            "result": {"url": None if page.is_closed() else page.url,
                       "reloaded": reloaded, "http_status": http_status,
                       "page_events": events, "event_scope": "reload_call_interval"},
            "observer_refs": {"l2": [], "l3": []}, "error": error,
        }

    def as_port(self):
        def prepare(request, assigned_task):
            return ReloadInput.model_validate(request["arguments"]).model_dump(mode="json")

        return ExecutionPort(
            description="Reload the assigned Page once and return the observed URL, HTTP status and reload completion. Completion means the requested wait_until was reached, not that content changed or the investigation is complete.",
            kind="tool", provenance="new_observation",
            permission_description="Uses the existing Page, current observation and event connection. Invalidates state before attempting reload. Caller owns serial Page access, network policy, timeout and follow-up observation; no automatic retry, state refresh, comparison, tab switch or storage.",
            prepare=prepare, invoke=self.execute,
        )
