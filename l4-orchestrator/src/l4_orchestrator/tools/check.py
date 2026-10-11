"""Ensure the exact observed native checkbox or radio is checked."""
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


class CheckTarget(WireModel):
    element_id: str = Field(min_length=1)


class CheckParams(WireModel):
    pass


class CheckInput(WireModel):
    action_id: str = Field(min_length=1)
    tool: Literal["check"]
    target: CheckTarget
    params: CheckParams
    context: ActionContext


_INSPECT = """node => {
    if (!node.isConnected || node.getRootNode() !== document) return {error: 'TARGET_STALE'};
    if (node.namespaceURI !== 'http://www.w3.org/1999/xhtml' || node.tagName !== 'INPUT' ||
        !['checkbox', 'radio'].includes(node.type)) return {error: 'BLOCKED_ACTION'};
    const box = node.getBoundingClientRect();
    if (!box.width || !box.height || ['hidden', 'collapse'].includes(getComputedStyle(node).visibility))
        return {error: 'ELEMENT_NOT_VISIBLE'};
    const owner = node.closest('[aria-disabled="true" i],[aria-disabled="false" i]');
    if (node.matches(':disabled') || node.closest('[inert]') ||
        owner?.getAttribute('aria-disabled').toLowerCase() === 'true') return {error: 'ELEMENT_DISABLED'};
    if (node.type === 'checkbox' && node.indeterminate) return {error: 'BLOCKED_ACTION'};
    return {error: null, type: node.type, checked: node.checked};
}"""

_VERIFY = """(node, expectedType) => {
    if (!node.isConnected || node.getRootNode() !== document) return 'TARGET_STALE';
    if (node.namespaceURI !== 'http://www.w3.org/1999/xhtml' || node.tagName !== 'INPUT' ||
        node.type !== expectedType || !node.checked ||
        (node.type === 'checkbox' && node.indeterminate)) return 'BLOCKED_ACTION';
    return null;
}"""

_MESSAGES = {
    "TARGET_STALE": "The observed control is no longer current. Query the page before another action.",
    "ELEMENT_NOT_FOUND": "The element ID was not found in the latest element observation.",
    "ELEMENT_NOT_VISIBLE": "The observed control is not visible.",
    "ELEMENT_DISABLED": "The control is disabled or inert, even if already checked.",
    "BLOCKED_ACTION": "Use a native checkbox or radio. Indeterminate checkboxes are unsupported. The same control and type must remain checked after the operation.",
    "ACTION_TIMEOUT": "Checking timed out. The control may already have changed. Query before deciding another action.",
    "PAGE_CLOSED": "The assigned Page is closed.",
    "BROWSER_CRASH": "The assigned Page crashed.",
    "INTERNAL_ERROR": "The checked state could not be confirmed. No automatic retry was performed.",
}


class CheckTool:
    def __init__(self, elements: ElementRegistry, *, timeout_ms: int, page_events: PageEvents):
        if type(timeout_ms) is not int or timeout_ms < 1:
            raise ValueError("timeout_ms must be a positive integer")
        if page_events.state is not elements.state:
            raise ValueError("Elements and events must belong to the same PageState")
        self.elements = elements
        self.timeout_ms = timeout_ms
        self.page_events = page_events

    async def execute(self, arguments):
        request = CheckInput.model_validate(arguments)
        if error := page_target_error(request, self.elements.state.page_id):
            return error
        state = self.elements.state
        started_at = datetime.now(timezone.utc).isoformat()
        started = perf_counter()
        before_id, after_id, node, checked = None, None, None, None
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
            status = "timeout" if code == "ACTION_TIMEOUT" else "failed"
            error = {"code": code, "message": _MESSAGES[code],
                     "recoverable": code not in {"PAGE_CLOSED", "BROWSER_CRASH"}}

        try:
            async with asyncio.timeout(self.timeout_ms / 1000):
                before_id = state.read(request.context.state_id)["state_id"]
                node = await self.elements.resolve(request.target.element_id, expected_state_id=before_id)
                control = await node.evaluate(_INSPECT)
                if control["error"]:
                    raise PageStateError(control["error"], _MESSAGES[control["error"]])
                state.read(before_id)
                if control["checked"]:
                    # Do not toggle or dispatch input/change for an already checked control.
                    code = await node.evaluate(_VERIFY, control["type"])
                    if code:
                        raise PageStateError(code, _MESSAGES[code])
                    state.read(before_id)
                    after_id = before_id
                else:
                    events = self.page_events.begin(request.action_id)
                    listening = True
                    state.invalidate()
                    remaining_ms = max(1, self.timeout_ms - (perf_counter() - started) * 1000)
                    try:
                        await node.check(force=False, timeout=remaining_ms)
                    except BrowserTimeoutError:
                        raise
                    except Error:
                        # Playwright itself can reject a reverted check or detached node.
                        # Preserve unknown completion even if the final state looks checked.
                        code = await node.evaluate(_VERIFY, control["type"])
                        if code:
                            raise PageStateError(code, _MESSAGES[code])
                        raise
                    code = await node.evaluate(_VERIFY, control["type"])
                    if code:
                        raise PageStateError(code, _MESSAGES[code])
                    state._check_page()
                checked = True
        except (TimeoutError, BrowserTimeoutError):
            fail("ACTION_TIMEOUT")
        except PageStateError as exc:
            fail(exc.code)
        except Error:
            code = "TARGET_STALE" if any(event["kind"] == "navigation" for event in events) else "INTERNAL_ERROR"
            fail(code)
        finally:
            if listening:
                self.page_events.end()
            if node is not None:
                try:
                    await node.dispose()
                except Error:
                    pass

        return {
            "action_id": request.action_id, "tool": "check", "status": status,
            "started_at": started_at, "finished_at": datetime.now(timezone.utc).isoformat(),
            "duration_ms": round((perf_counter() - started) * 1000),
            "before_state_id": before_id, "after_state_id": after_id,
            "result": {"element_id": request.target.element_id, "checked": checked,
                       "page_events": events, "event_scope": "check_call_interval"},
            "observer_refs": {"l2": [], "l3": []}, "error": error,
        }

    def as_port(self):
        def prepare(request, assigned_task):
            return CheckInput.model_validate(request["arguments"]).model_dump(mode="json")

        return ExecutionPort(
            description="Ensure an observed native HTML checkbox or radio is checked. params must be empty. Already checked controls succeed without input. Returns checked=true only after verification; null on failure does not mean unchecked. Radio selection can clear another radio in the same group.",
            kind="tool", provenance="new_observation",
            permission_description="Uses the exact observed node without force or replacement lookup. Validates visibility and enabled state even if already checked. Rejects indeterminate checkboxes. Invalidates PageState before a check attempt. No uncheck, custom controls, submission command, retry, automatic observation or file storage. The caller owns serial Page access, page events and network policy.",
            prepare=prepare, invoke=self.execute,
        )
