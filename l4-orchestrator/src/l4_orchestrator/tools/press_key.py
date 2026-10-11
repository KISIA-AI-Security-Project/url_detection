"""Press Enter once on one observed native text control, without judging submission."""
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


class PressKeyTarget(WireModel):
    element_id: str = Field(min_length=1)


class PressKeyParams(WireModel):
    key: Literal["Enter"]


class PressKeyInput(WireModel):
    action_id: str = Field(min_length=1)
    tool: Literal["press_key"]
    target: PressKeyTarget
    params: PressKeyParams
    context: ActionContext


_CHECK = """(node, focused) => {
    if (!node.isConnected || node.getRootNode() !== document) return 'TARGET_STALE';
    const supported = node.namespaceURI === 'http://www.w3.org/1999/xhtml' &&
        (node.tagName === 'TEXTAREA' || (node.tagName === 'INPUT' &&
          ['text', 'search', 'email', 'password', 'tel', 'url'].includes(node.type)));
    if (!supported) return 'BLOCKED_ACTION';
    const box = node.getBoundingClientRect();
    if (!box.width || !box.height || ['hidden', 'collapse'].includes(getComputedStyle(node).visibility))
        return 'ELEMENT_NOT_VISIBLE';
    const owner = node.closest('[aria-disabled="true" i],[aria-disabled="false" i]');
    if (node.matches(':disabled') || node.closest('[inert]') ||
        owner?.getAttribute('aria-disabled').toLowerCase() === 'true') return 'ELEMENT_DISABLED';
    if (node.readOnly || node.getAttribute('aria-readonly')?.toLowerCase() === 'true')
        return 'BLOCKED_ACTION';
    if (focused && document.activeElement !== node) return 'BLOCKED_ACTION';
    return null;
}"""

_MESSAGES = {
    "TARGET_STALE": "The observed state or input is no longer current. Query the elements again.",
    "ELEMENT_NOT_FOUND": "The element ID is absent from the latest successful element query.",
    "ELEMENT_NOT_VISIBLE": "The observed input is not visible.",
    "ELEMENT_DISABLED": "The observed input is disabled or inert.",
    "BLOCKED_ACTION": "Enter requires a supported writable native text control that retains focus.",
    "PAGE_CLOSED": "The supplied Page is closed.",
    "BROWSER_CRASH": "The supplied Page crashed.",
    "ACTION_TIMEOUT": "The Enter operation timed out. If pressed is null, input may already have occurred; observe before another action.",
    "INTERNAL_ERROR": "The Enter operation did not complete. No automatic retry was performed.",
}


class PressKeyTool:
    def __init__(self, elements: ElementRegistry, *, timeout_ms: int, page_events: PageEvents):
        if type(timeout_ms) is not int or timeout_ms < 1:
            raise ValueError("timeout_ms must be a positive integer")
        if page_events.state is not elements.state:
            raise ValueError("Elements and events must belong to the same PageState")
        self.elements = elements
        self.timeout_ms = timeout_ms
        self.page_events = page_events

    async def execute(self, arguments):
        request = PressKeyInput.model_validate(arguments)
        if error := page_target_error(request, self.elements.state.page_id):
            return error
        page, state = self.elements.page, self.elements.state
        started_at = datetime.now(timezone.utc).isoformat()
        started = perf_counter()
        before_id, node, error = None, None, None
        pressed = False  # None only after starting the keyboard command.
        status, events, listening, crashed = "success", [], False, False

        def on_crash(*args):
            nonlocal crashed
            crashed = True

        def fail(code):
            nonlocal error, status
            if code == "STATE_CHANGED":
                code = "TARGET_STALE"
            if code not in _MESSAGES:
                code = "INTERNAL_ERROR"
            status = "timeout" if code == "ACTION_TIMEOUT" else "failed"
            error = {"code": code, "message": _MESSAGES[code],
                     "recoverable": code not in {"PAGE_CLOSED", "BROWSER_CRASH"}}

        async def check_node(*, focused=False):
            code = await node.evaluate(_CHECK, focused)
            if code:
                raise PageStateError(code, _MESSAGES[code])

        try:
            async with asyncio.timeout(self.timeout_ms / 1000):
                before_id = state.read(request.context.state_id)["state_id"]
                node = await self.elements.resolve(request.target.element_id, expected_state_id=before_id)
                await check_node()
                state.read(before_id)
                events = self.page_events.begin(request.action_id)
                page.on("crash", on_crash)
                listening = True
                # Focus can run page handlers even when no key is ultimately sent.
                state.invalidate()
                await node.focus()
                await check_node(focused=True)
                # Do not focus again or rematch another node after the final check.
                pressed = None
                await page.keyboard.press(request.params.key)
                pressed = True
        except (TimeoutError, BrowserTimeoutError):
            fail("ACTION_TIMEOUT")
        except PageStateError as exc:
            fail(exc.code)
        except Error:
            fail("BROWSER_CRASH" if crashed else "PAGE_CLOSED" if page.is_closed() else "INTERNAL_ERROR")
        finally:
            if listening:
                self.page_events.end()
                page.remove_listener("crash", on_crash)
            if node is not None:
                try:
                    await node.dispose()
                except Error:
                    pass  # Navigation/closure may already have destroyed the handle.

        return {
            "action_id": request.action_id, "tool": "press_key", "status": status,
            "started_at": started_at, "finished_at": datetime.now(timezone.utc).isoformat(),
            "duration_ms": round((perf_counter() - started) * 1000),
            "before_state_id": before_id, "after_state_id": None,
            "result": {"element_id": request.target.element_id, "key": request.params.key,
                       "pressed": pressed, "page_events": events, "event_scope": "press_key_call_interval"},
            "observer_refs": {"l2": [], "l3": []}, "error": error,
        }

    def as_port(self):
        def prepare(request, assigned_task):
            return PressKeyInput.model_validate(request["arguments"]).model_dump(mode="json")

        return ExecutionPort(
            description="Press Enter once on the exact native input or textarea from the current element query. Returns keyboard command completion and page events observed during the call, not submission or server receipt.",
            kind="tool", provenance="new_observation",
            permission_description="Only Enter and a supported visible, enabled, writable text control are accepted. Rechecks the original node and focus before sending the key. Invalidates PageState before focus. The caller owns serial Page access, network policy, popup handling and later observation. No automatic retry or storage.",
            prepare=prepare, invoke=self.execute,
        )
