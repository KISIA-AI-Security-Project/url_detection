"""One native history-back action on the caller's existing Chromium Page."""
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


class GoBackParams(WireModel):
    wait_until: Literal["commit", "domcontentloaded", "load", "networkidle"] = "domcontentloaded"


class GoBackInput(WireModel):
    action_id: str = Field(min_length=1)
    tool: Literal["go_back"]
    target: None
    params: GoBackParams
    context: ActionContext


_MESSAGES = {
    "TARGET_STALE": "The requested observation is no longer current. Observe before deciding another action.",
    "NAVIGATION_TIMEOUT": "History navigation timed out. It may complete later; observe before deciding another action. No automatic retry was performed.",
    "HISTORY_MOVEMENT_UNCONFIRMED": "The browser returned, but one backward history step could not be confirmed. Observe the current page before deciding another action.",
    "UNSUPPORTED_BROWSER": "History verification currently requires Chromium, including Chrome or Edge.",
    "PAGE_CLOSED": "The assigned Page is closed.",
    "BROWSER_CRASH": "The assigned Page crashed.",
    "INTERNAL_ERROR": "History navigation could not be completed. No automatic retry was performed.",
}


class GoBackTool:
    def __init__(self, state: PageState, *, timeout_ms: int, page_events: PageEvents):
        if type(timeout_ms) is not int or timeout_ms < 1:
            raise ValueError("timeout_ms must be a positive integer")
        if page_events.state is not state:
            raise ValueError("State and events must belong to the same PageState")
        self.state = state
        self.timeout_ms = timeout_ms
        self.page_events = page_events
        self._cleanup_tasks = set()

    async def _release_session(self, creation):
        try:
            session = await creation
            await session.detach()
        except Error:
            pass  # The Page/context may already have closed.

    async def execute(self, arguments):
        request = GoBackInput.model_validate(arguments)
        if error := page_target_error(request, self.state.page_id):
            return error
        state, page = self.state, self.state.page
        started_at = datetime.now(timezone.utc).isoformat()
        started = perf_counter()
        before_id, previous_url, http_status, error, session_task = None, None, None, None, None
        status, attempted, moved = "success", False, False
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
                     "recoverable": code not in {"PAGE_CLOSED", "BROWSER_CRASH", "UNSUPPORTED_BROWSER"}}

        try:
            async with asyncio.timeout(self.timeout_ms / 1000):
                before_id = state.read(request.context.state_id)["state_id"]
                previous_url = page.url
                browser = page.context.browser
                if browser is not None and browser.browser_type.name != "chromium":
                    raise PageStateError("UNSUPPORTED_BROWSER", _MESSAGES["UNSUPPORTED_BROWSER"])
                events = self.page_events.begin(request.action_id)
                page.on("crash", on_crash)
                listening = True
                # Read Chromium's real history; neither URL nor a None response proves no movement.
                # Creation may reach the browser before its reply reaches Python.
                # Keep ownership through timeout/cancellation so late replies can be released.
                session_task = asyncio.create_task(page.context.new_cdp_session(page))
                session = await asyncio.shield(session_task)
                before = await session.send("Page.getNavigationHistory")
                before_index = before["currentIndex"]
                before_entry = before["entries"][before_index]
                state.read(before_id)
                if before_index == 0:
                    status = "no_effect"  # Includes a first entry with forward entries remaining.
                else:
                    state.invalidate()
                    attempted, moved = True, None
                    remaining_ms = max(1, self.timeout_ms - (perf_counter() - started) * 1000)
                    response = await page.go_back(wait_until=request.params.wait_until, timeout=remaining_ms)
                    after = await session.send("Page.getNavigationHistory")
                    after_index = after["currentIndex"]
                    after_entry = after["entries"][after_index]
                    # Redirects can replace an entry; same-document steps may keep the same URL.
                    if after_index != before_index - 1 or after_entry["id"] == before_entry["id"]:
                        raise PageStateError("HISTORY_MOVEMENT_UNCONFIRMED", _MESSAGES["HISTORY_MOVEMENT_UNCONFIRMED"])
                    moved = True
                    http_status = response.status if response is not None else None
        except (TimeoutError, BrowserTimeoutError):
            fail("NAVIGATION_TIMEOUT")
        except PageStateError as exc:
            fail(exc.code)
        except Error:
            fail("BROWSER_CRASH" if crashed else "PAGE_CLOSED" if page.is_closed() else "INTERNAL_ERROR")
        finally:
            if listening:
                self.page_events.end()
                page.remove_listener("crash", on_crash)
            if session_task is not None:
                cleanup = asyncio.create_task(self._release_session(session_task))
                self._cleanup_tasks.add(cleanup)
                cleanup.add_done_callback(self._cleanup_tasks.discard)
                try:
                    async with asyncio.timeout(self.timeout_ms / 1000):
                        await asyncio.shield(cleanup)
                except TimeoutError:
                    pass  # Cleanup retains ownership and releases a late-created session.

        return {
            "action_id": request.action_id, "tool": "go_back", "status": status,
            "started_at": started_at, "finished_at": datetime.now(timezone.utc).isoformat(),
            "duration_ms": round((perf_counter() - started) * 1000),
            "before_state_id": before_id, "after_state_id": None,
            "result": {"previous_url": previous_url,
                       "current_url": None if page.is_closed() else page.url,
                       "attempted": attempted, "moved": moved, "http_status": http_status,
                       "page_events": events, "event_scope": "go_back_call_interval"},
            "observer_refs": {"l2": [], "l3": []}, "error": error,
        }

    def as_port(self):
        def prepare(request, assigned_task):
            return GoBackInput.model_validate(request["arguments"]).model_dump(mode="json")

        return ExecutionPort(
            description="Go back one browser history entry in the assigned Chromium Page. Reports no_effect only when the browser has no previous entry. Same-URL history changes can still be successful. This is not an undo or a saved-page restore.",
            kind="tool", provenance="new_observation",
            permission_description="Uses the caller's existing Page, state and event connection. Invalidates state before a single native go_back attempt; no automatic retry, refresh, tab switch or storage. Caller owns serial Page access, network policy, timeout and follow-up observation.",
            prepare=prepare, invoke=self.execute,
        )
