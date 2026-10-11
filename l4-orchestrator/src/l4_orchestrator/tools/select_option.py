"""Select one existing option on the exact observed native, single-select control."""
import asyncio
from datetime import datetime, timezone
from time import perf_counter
from typing import Literal

from playwright.async_api import Error, TimeoutError as BrowserTimeoutError
from pydantic import Field, StrictStr

from ..elements import ElementRegistry
from ..page_events import PageEvents
from ..page_state import PageStateError
from ..ports import ExecutionPort
from ..schemas import WireModel
from .schemas import ActionContext, page_target_error


class SelectTarget(WireModel):
    element_id: str = Field(min_length=1)


class SelectByValue(WireModel):
    value: StrictStr


class SelectByLabel(WireModel):
    label: StrictStr


class SelectByIndex(WireModel):
    index: int = Field(strict=True, ge=0)


class SelectOptionInput(WireModel):
    action_id: str = Field(min_length=1)
    tool: Literal["select_option"]
    target: SelectTarget
    params: SelectByValue | SelectByLabel | SelectByIndex
    context: ActionContext


_RESOLVE_OPTION = """(node, requested) => {
    if (!node.isConnected || node.getRootNode() !== document) return {error: 'TARGET_STALE'};
    if (node.namespaceURI !== 'http://www.w3.org/1999/xhtml' || node.tagName !== 'SELECT' || node.multiple)
        return {error: 'BLOCKED_ACTION'};
    const box = node.getBoundingClientRect();
    if (!box.width || !box.height || ['hidden', 'collapse'].includes(getComputedStyle(node).visibility))
        return {error: 'ELEMENT_NOT_VISIBLE'};
    const owner = node.closest('[aria-disabled="true" i],[aria-disabled="false" i]');
    if (node.matches(':disabled') || node.closest('[inert]') ||
        owner?.getAttribute('aria-disabled').toLowerCase() === 'true') return {error: 'ELEMENT_DISABLED'};
    const matches = Array.from(node.options).filter((option, index) =>
        'value' in requested ? option.value === requested.value :
        'label' in requested ? option.label === requested.label : index === requested.index);
    if (!matches.length) return {error: 'ELEMENT_NOT_FOUND'};
    if (matches.length !== 1) return {error: 'BLOCKED_ACTION'};
    const option = matches[0];
    const optionOwner = option.closest('[aria-disabled="true" i],[aria-disabled="false" i]');
    if (option.matches(':disabled') || option.closest('[inert]') ||
        optionOwner?.getAttribute('aria-disabled').toLowerCase() === 'true') return {error: 'ELEMENT_DISABLED'};
    return {node, option, value: option.value, error: null};
}"""

_VERIFY = """selection => {
    const {node, option, value} = selection;
    if (!node.isConnected || node.getRootNode() !== document || !option.isConnected ||
        option.closest('select') !== node) return {error: 'TARGET_STALE'};
    if (node.multiple || node.selectedOptions.length !== 1 || node.selectedOptions[0] !== option ||
        option.value !== value) return {error: 'BLOCKED_ACTION'};
    return {error: null, value: option.value};
}"""

_MESSAGES = {
    "TARGET_STALE": "The observed select or option is no longer current. Query the page before another action.",
    "ELEMENT_NOT_FOUND": "The element ID or requested option was not found in the current select.",
    "ELEMENT_NOT_VISIBLE": "The observed select is not visible.",
    "ELEMENT_DISABLED": "The select or requested option is disabled or inert.",
    "BLOCKED_ACTION": "Use a native single-select and one unambiguous option. Use index for duplicate values or labels. The requested selection must remain verifiable after the operation.",
    "ACTION_TIMEOUT": "Selection timed out. If selected is null, selection may already have occurred. Query before deciding another action.",
    "PAGE_CLOSED": "The assigned Page is closed.",
    "BROWSER_CRASH": "The assigned Page crashed.",
    "INTERNAL_ERROR": "Selection could not be confirmed. No automatic retry was performed.",
}


class SelectOptionTool:
    def __init__(self, elements: ElementRegistry, *, timeout_ms: int, page_events: PageEvents):
        if type(timeout_ms) is not int or timeout_ms < 1:
            raise ValueError("timeout_ms must be a positive integer")
        if page_events.state is not elements.state:
            raise ValueError("Elements and events must belong to the same PageState")
        self.elements = elements
        self.timeout_ms = timeout_ms
        self.page_events = page_events

    async def execute(self, arguments):
        request = SelectOptionInput.model_validate(arguments)
        if error := page_target_error(request, self.elements.state.page_id):
            return error
        page, state = self.elements.page, self.elements.state
        started_at = datetime.now(timezone.utc).isoformat()
        started = perf_counter()
        before_id, node, selection, option_ref = None, None, None, None
        selected, selected_value = False, None
        status, error, events, listening = "success", None, [], False

        def fail(code):
            nonlocal status, error
            # Known terminal events also take precedence over a subsequent timeout.
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
                selection = await node.evaluate_handle(_RESOLVE_OPTION, request.params.model_dump())
                code = await selection.evaluate("selection => selection.error")
                if code:
                    raise PageStateError(code, _MESSAGES[code])
                option_ref = await selection.get_property("option")
                option = option_ref.as_element()
                if option is None:
                    raise PageStateError("TARGET_STALE", _MESSAGES["TARGET_STALE"])
                state.read(before_id)
                events = self.page_events.begin(request.action_id)
                listening = True
                state.invalidate()
                selected = None
                # Pass the exact option node, not a value/index that could match a replacement.
                remaining_ms = max(1, self.timeout_ms - (perf_counter() - started) * 1000)
                await node.select_option(element=option, force=False, timeout=remaining_ms)
                verified = await selection.evaluate(_VERIFY)
                if verified["error"]:
                    raise PageStateError(verified["error"], _MESSAGES[verified["error"]])
                state._check_page()
                selected, selected_value = True, verified["value"]
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
            for handle in (option_ref, selection, node):
                if handle is not None:
                    try:
                        await handle.dispose()
                    except Error:
                        pass  # A navigated/closed page may already have released the handles.

        return {
            "action_id": request.action_id, "tool": "select_option", "status": status,
            "started_at": started_at, "finished_at": datetime.now(timezone.utc).isoformat(),
            "duration_ms": round((perf_counter() - started) * 1000),
            "before_state_id": before_id, "after_state_id": None,
            "result": {"element_id": request.target.element_id, "selected": selected,
                       "selected_value": selected_value, "page_events": events,
                       "event_scope": "select_option_call_interval"},
            "observer_refs": {"l2": [], "l3": []}, "error": error,
        }

    def as_port(self):
        def prepare(request, assigned_task):
            return SelectOptionInput.model_validate(request["arguments"]).model_dump(mode="json")

        return ExecutionPort(
            description="Select one option on an observed native HTML single-select. Pass exactly one of value, label or zero-based index using the options from get_page_state with include=['elements']. Reject ambiguous matches. Returns the confirmed selected value, not the site's outcome.",
            kind="tool", provenance="new_observation",
            permission_description="Uses the exact observed select and resolved option without force or replacement lookup. Invalidates PageState before the attempt. No custom menus, multiple selection, automatic submission, retry, observation or file storage. The caller owns serial Page access, page events and network policy.",
            prepare=prepare, invoke=self.execute,
        )
