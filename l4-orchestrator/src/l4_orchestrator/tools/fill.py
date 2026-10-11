"""Put a fixed analysis-only dummy value into one previously observed native control."""
import asyncio
from datetime import datetime, timezone
from time import perf_counter
from types import MappingProxyType
from typing import Literal

from playwright.async_api import Error, TimeoutError as BrowserTimeoutError
from pydantic import Field, StrictBool, ValidationError

from ..elements import ElementRegistry
from ..page_events import PageEvents
from ..page_state import PageStateError
from ..ports import ExecutionPort
from ..schemas import WireModel
from .schemas import ActionContext, page_target_error


DummyType = Literal["dummy_username", "dummy_email", "dummy_password", "dummy_phone", "dummy_text"]
_PRESETS = MappingProxyType({
    "dummy_username": "l4_test_user",
    "dummy_email": "l4-test@example.com",
    "dummy_password": "L4-Dummy-Only!27",
    "dummy_phone": "00000000000",
    "dummy_text": "L4 analysis test",
})


class FillTarget(WireModel):
    element_id: str = Field(min_length=1)


class FillParams(WireModel):
    value_type: DummyType
    clear_first: StrictBool = True


class FillInput(WireModel):
    action_id: str = Field(min_length=1)
    tool: Literal["fill"]
    target: FillTarget
    params: FillParams
    context: ActionContext


def _parse(arguments):
    try:
        return FillInput.model_validate(arguments)
    except ValidationError:
        # Pydantic normally includes rejected input values in its exception text.
        raise ValueError("Invalid fill request: use an element ID, a supported dummy value_type and a boolean clear_first; arbitrary values are not accepted.") from None


_CHECK = """(node, options) => {
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
    const wantedLength = options.length + (options.clearFirst ? 0 : node.value.length);
    if (node.maxLength >= 0 && wantedLength > node.maxLength) return 'BLOCKED_ACTION';
    return null;
}"""

_WATCH_INPUT = """watch => {
    const node = watch.node;
    watch.onInput = event => {
        if (!event.isTrusted) return;
        if (event.target === node) watch.inputOnTarget++;
        else watch.otherInput = true;
    };
    watch.guard = event => {
        if (!event.isTrusted) return;
        // Bubble phase sees focus changes from the target's own beforeinput handler.
        if (event.defaultPrevented || !node.isConnected || event.target !== node ||
            document.activeElement !== node) {
            event.preventDefault();
            watch.blocked = true;
        }
    };
    document.addEventListener('input', watch.onInput, true);
    document.addEventListener('beforeinput', watch.guard, false);
    watch.cleanup = () => {
        document.removeEventListener('input', watch.onInput, true);
        document.removeEventListener('beforeinput', watch.guard, false);
    };
}"""

_MESSAGES = {
    "TARGET_STALE": "The observed state or element is no longer current. Observe again before deciding another action.",
    "ELEMENT_NOT_FOUND": "The element ID is absent from the latest successful element query.",
    "ELEMENT_NOT_VISIBLE": "The observed input is not visible.",
    "ELEMENT_DISABLED": "The observed input is disabled or inert.",
    "BLOCKED_ACTION": "The input is unsupported, read-only, has insufficient capacity, or the requested input position/value could not be confirmed.",
    "ACTION_TIMEOUT": "The fill operation timed out. If filled is null, input may already have occurred. No automatic retry was performed.",
    "PAGE_CLOSED": "The assigned Page is closed.",
    "BROWSER_CRASH": "The assigned Page crashed.",
    "INTERNAL_ERROR": "The fill operation did not complete. No automatic retry was performed.",
}


class FillTool:
    def __init__(self, elements: ElementRegistry, *, timeout_ms: int, page_events: PageEvents):
        if type(timeout_ms) is not int or timeout_ms < 1:
            raise ValueError("timeout_ms must be a positive integer")
        if page_events.state is not elements.state:
            raise ValueError("Elements and events must belong to the same PageState")
        self.elements = elements
        self.timeout_ms = timeout_ms
        self.page_events = page_events

    async def execute(self, arguments):
        request = _parse(arguments)
        if error := page_target_error(request, self.elements.state.page_id):
            return error
        value = _PRESETS[request.params.value_type]
        page, state = self.elements.page, self.elements.state
        started_at = datetime.now(timezone.utc).isoformat()
        started = perf_counter()
        before_id, node, expected, error = None, None, None, None
        filled = False
        status, events, listening, crashed = "success", [], False, False

        def on_crash(*args):
            nonlocal crashed
            crashed = True

        def remaining_ms():
            return max(1, self.timeout_ms - (perf_counter() - started) * 1000)

        async def check_node(*, focused=False):
            code = await node.evaluate(_CHECK, {"clearFirst": request.params.clear_first, "length": len(value)})
            if code:
                raise PageStateError(code, _MESSAGES.get(code, _MESSAGES["INTERNAL_ERROR"]))
            if focused and not await node.evaluate("node => document.activeElement === node"):
                raise PageStateError("BLOCKED_ACTION", _MESSAGES["BLOCKED_ACTION"])

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
                await check_node()
                state.read(before_id)
                events = self.page_events.begin(request.action_id)
                page.on("crash", on_crash)
                listening = True
                state.invalidate()
                filled = None
                # Focusing can run page handlers. Recheck the same node before sending text.
                await node.focus()
                await check_node(focused=True)
                # Keep prior/expected text and temporary input checks inside the browser.
                # Only a boolean comes back; equal text alone is not proof of actual input.
                expected = await node.evaluate_handle("""(node, options) => ({node,
                    value: options.replace ? options.value : node.value + options.value,
                    inputOnTarget: 0, otherInput: false, blocked: false})""",
                    {"replace": request.params.clear_first, "value": value})
                # Own the handle BEFORE adding listeners, so timeout/cancel during
                # installation still has a cleanup route. Installation returns no values.
                await expected.evaluate(_WATCH_INPUT)
                if request.params.clear_first:
                    await node.fill(value, force=False, timeout=remaining_ms())
                else:
                    # Native End works for email too, whose selection API is unavailable.
                    # Control/Meta + End reaches the end of an entire multiline textarea.
                    await node.press("ControlOrMeta+End", timeout=remaining_ms())
                    await check_node(focused=True)
                    at_end = await node.evaluate("""node => node.selectionStart === null ||
                        (node.selectionStart === node.value.length && node.selectionEnd === node.value.length)""")
                    if not at_end:
                        raise PageStateError("BLOCKED_ACTION", _MESSAGES["BLOCKED_ACTION"])
                    await page.keyboard.insert_text(value)
                matches = await expected.evaluate("""item => !item.blocked && !item.otherInput &&
                    item.inputOnTarget > 0 && item.node.isConnected && item.node.value === item.value""")
                if not matches:
                    raise PageStateError("BLOCKED_ACTION", _MESSAGES["BLOCKED_ACTION"])
                filled = True
        except (TimeoutError, BrowserTimeoutError):
            fail("ACTION_TIMEOUT")
        except PageStateError as exc:
            fail(exc.code)  # Do not echo browser error text or rejected/previous values.
        except Exception:
            # Playwright and caller errors can embed input strings. Keep fixed messages only.
            code = "BROWSER_CRASH" if crashed else "PAGE_CLOSED" if page.is_closed() else "INTERNAL_ERROR"
            if code == "INTERNAL_ERROR" and node is not None:
                try:
                    async with asyncio.timeout(self.timeout_ms / 1000):
                        if not await node.evaluate("node => node.isConnected && node.getRootNode() === document"):
                            code = "TARGET_STALE"
                except Exception:
                    pass
            fail(code)
        finally:
            if listening:
                self.page_events.end()
                page.remove_listener("crash", on_crash)
            if expected is not None:
                try:
                    await expected.evaluate("item => item.cleanup?.()")
                except Error:
                    pass  # Navigation/closure destroys the old document and its listeners.
            for handle in (expected, node):
                if handle is None:
                    continue
                try:
                    await handle.dispose()
                except Error:
                    pass

        # A page can copy input into its URL with arbitrary encoding. Do not echo any
        # event URL in fill's ToolResult. The caller's PageEvents remains a live browser feed.
        reports = [{**event, "url": None, "url_omitted": True} for event in events]
        return {
            "action_id": request.action_id, "tool": "fill", "status": status,
            "started_at": started_at, "finished_at": datetime.now(timezone.utc).isoformat(),
            "duration_ms": round((perf_counter() - started) * 1000),
            "before_state_id": before_id, "after_state_id": None,
            "result": {"element_id": request.target.element_id, "value_type": request.params.value_type,
                       "filled": filled, "page_events": reports, "event_scope": "fill_call_interval"},
            "observer_refs": {"l2": [], "l3": []}, "error": error,
        }

    def as_port(self):
        def prepare(request, assigned_task):
            return _parse(request["arguments"]).model_dump(mode="json")

        return ExecutionPort(
            description="Fill the exact previously observed native input or textarea with a fixed analysis-only dummy preset. Replace its content or append at its end. Returns action completion, not the application's outcome.",
            kind="tool", provenance="new_observation",
            permission_description="Only five dummy value_type names are accepted, never arbitrary input strings. Checks supported type, current observation, visibility, enabled and writable state. Invalidates PageState before input. No automatic submission, refresh, retry or storage. The caller owns serial Page access, page events and network policy.",
            prepare=prepare, invoke=self.execute,
        )
