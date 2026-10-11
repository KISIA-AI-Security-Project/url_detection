"""Bounded condition checks on the caller's Page, with no browser input."""
import asyncio
from datetime import datetime, timezone
import hashlib
from time import perf_counter
from typing import Annotated, Literal

from playwright.async_api import Error, TimeoutError as BrowserTimeoutError
from pydantic import Field, model_validator

from ..elements import ElementRegistry
from ..page_events import PageEvents
from ..page_state import PageStateError
from ..ports import ExecutionPort
from ..schemas import WireModel
from .schemas import ActionContext, page_target_error


class WaitTarget(WireModel):
    element_id: str = Field(min_length=1)


class WaitParams(WireModel):
    timeout_ms: int = Field(strict=True, ge=1)


class ElementWait(WaitParams):
    condition: Literal["visible", "hidden"]


class ChangeWait(WaitParams):
    condition: Literal["url_change", "dom_change"]


class LoadWait(WaitParams):
    condition: Literal["load_state"]
    state: Literal["domcontentloaded", "load"] = "load"


class TimedWait(WaitParams):
    condition: Literal["timeout"]


class WaitForInput(WireModel):
    action_id: str = Field(min_length=1)
    tool: Literal["wait_for"]
    target: WaitTarget | None
    params: Annotated[ElementWait | ChangeWait | LoadWait | TimedWait, Field(discriminator="condition")]
    context: ActionContext

    @model_validator(mode="after")
    def target_matches_condition(self):
        needs_element = self.params.condition in {"visible", "hidden"}
        if needs_element != (self.target is not None):
            raise ValueError("visible/hidden require target.element_id; other conditions require target=null")
        return self


_ELEMENT_STATUS = """node => {
    if (node.ownerDocument !== document || (node.isConnected && node.getRootNode() !== document))
        return {stale: true, detached: false, visible: false};
    const box = node.getBoundingClientRect();
    return {stale: false, detached: !node.isConnected,
        visible: node.isConnected && box.width > 0 && box.height > 0 &&
            !['hidden', 'collapse'].includes(getComputedStyle(node).visibility)};
}"""

_MESSAGES = {
    "TARGET_STALE": "The comparison baseline or original document/node is no longer available. Query before another action.",
    "ELEMENT_NOT_FOUND": "The target ID was not registered in the comparison baseline. Unknown IDs do not satisfy hidden.",
    "BLOCKED_ACTION": "Requested timeout_ms exceeds the caller's max_timeout_ms. The request was not shortened or executed.",
    "ACTION_TIMEOUT": "The requested condition was not confirmed within timeout_ms. No automatic retry was performed.",
    "PAGE_CLOSED": "The assigned Page is closed.",
    "BROWSER_CRASH": "The assigned Page crashed.",
    "INTERNAL_ERROR": "The wait could not confirm its condition. Query before deciding another action.",
}


class WaitForTool:
    def __init__(self, elements: ElementRegistry, *, max_timeout_ms: int, page_events: PageEvents):
        if type(max_timeout_ms) is not int or max_timeout_ms < 1:
            raise ValueError("max_timeout_ms must be a positive integer")
        if page_events.state is not elements.state:
            raise ValueError("Elements and events must belong to the same PageState")
        self.elements = elements
        self.max_timeout_ms = max_timeout_ms
        self.page_events = page_events

    async def execute(self, arguments):
        request = WaitForInput.model_validate(arguments)
        if error := page_target_error(request, self.elements.state.page_id):
            return error
        state, page = self.elements.state, self.elements.page
        condition = request.params.condition
        started_at, started = datetime.now(timezone.utc).isoformat(), perf_counter()
        deadline = asyncio.get_running_loop().time() + request.params.timeout_ms / 1000
        before_id, node, satisfied = None, None, None
        status, error, events, listening = "success", None, [], False

        def fail(code):
            nonlocal status, error
            try:
                state._check_page()
            except PageStateError as terminal:
                code = terminal.code
            if code == "STATE_CHANGED":
                code = "TARGET_STALE"
            if code not in _MESSAGES:
                code = "INTERNAL_ERROR"
            status = "blocked" if code == "BLOCKED_ACTION" else "timeout" if code == "ACTION_TIMEOUT" else "failed"
            error = {"code": code, "message": _MESSAGES[code],
                     "recoverable": code not in {"PAGE_CLOSED", "BROWSER_CRASH"}}

        async def sample(baseline):
            state._check_page()
            if baseline is not None:
                state.read_comparison(before_id)
            if condition in {"visible", "hidden"}:
                current = await node.evaluate(_ELEMENT_STATUS)
                state._check_page()
                if current["stale"] or (condition == "visible" and current["detached"]):
                    raise PageStateError("TARGET_STALE", _MESSAGES["TARGET_STALE"])
                return current["visible"] if condition == "visible" else not current["visible"]
            if condition == "url_change":
                return page.url != baseline["url"]
            try:
                html = await page.evaluate("() => document.documentElement?.outerHTML ?? null")
            except Error as exc:
                state._check_page()
                if "Execution context was destroyed, most likely because of a navigation" in str(exc):
                    return False  # Context loss can precede the navigation event; keep the same deadline.
                raise
            state._check_page()
            return html is not None and "sha256:" + hashlib.sha256(html.encode("utf-8")).hexdigest() != baseline["dom_fingerprint"]

        try:
            state._check_page()
            if request.params.timeout_ms > self.max_timeout_ms:
                raise PageStateError("BLOCKED_ACTION", _MESSAGES["BLOCKED_ACTION"])
            needs_baseline = condition in {"visible", "hidden", "url_change", "dom_change"}
            baseline = state.read_comparison(request.context.state_id) if needs_baseline or request.context.state_id is not None else None
            before_id = baseline["state_id"] if baseline is not None else None
            # All accepted waits leave the next action to a fresh query. This does
            # not reload the browser or restore the comparison as usable action state.
            state.invalidate()
            events = self.page_events.begin(request.action_id)
            listening = True
            if condition == "timeout":
                # Time elapsed is the condition itself, not a caught TimeoutError.
                while True:
                    state._check_page()
                    remaining = deadline - asyncio.get_running_loop().time()
                    if remaining <= 0:
                        break
                    await asyncio.sleep(min(0.05, remaining))
            else:
                async with asyncio.timeout_at(deadline):
                    if condition in {"visible", "hidden"}:
                        node = await self.elements.resolve_for_wait(request.target.element_id, expected_state_id=before_id)
                    if condition == "load_state":
                        remaining_ms = max(1, (deadline - asyncio.get_running_loop().time()) * 1000)
                        await page.wait_for_load_state(request.params.state, timeout=remaining_ms)
                    else:
                        while not await sample(baseline):
                            await asyncio.sleep(0.05)
            state._check_page()
            if baseline is not None:
                state.read_comparison(before_id)
            satisfied = True
        except (TimeoutError, BrowserTimeoutError):
            fail("ACTION_TIMEOUT")
        except PageStateError as exc:
            fail(exc.code)
        except Error:
            fail("TARGET_STALE" if condition in {"visible", "hidden"} else "INTERNAL_ERROR")
        finally:
            if listening:
                self.page_events.end()
            if node is not None:
                try:
                    await node.dispose()
                except Error:
                    pass

        return {
            "action_id": request.action_id, "tool": "wait_for", "status": status,
            "started_at": started_at, "finished_at": datetime.now(timezone.utc).isoformat(),
            "duration_ms": round((perf_counter() - started) * 1000),
            "before_state_id": before_id, "after_state_id": None,
            "result": {"condition": condition, "satisfied": satisfied,
                       "page_events": events, "event_scope": "wait_for_call_interval"},
            "observer_refs": {"l2": [], "l3": []}, "error": error,
        }

    def as_port(self):
        def prepare(request, assigned_task):
            return WaitForInput.model_validate(request["arguments"]).model_dump(mode="json")

        return ExecutionPort(
            description="Wait for visible/hidden on a previously registered original node, URL/HTML change from the latest comparison baseline, current-document load_state (domcontentloaded/load), or fixed timeout elapsed. params.timeout_ms is required and caller-limited. context.state_id=null uses the latest baseline for comparison conditions without collecting. satisfied=true confirms only that condition; null means not confirmed. Query before the next action.",
            kind="tool", provenance="new_observation",
            permission_description="Reads the same Page without browser input or selector rematching. Uses a comparison-only baseline after actions; strict action-state checks are unchanged. Original-node removal satisfies hidden but replacement documents are stale for element waits. No file storage, screenshots, automatic fresh observation or action retry. The caller owns serial Page access, page events and network policy.",
            prepare=prepare, invoke=self.execute,
        )
