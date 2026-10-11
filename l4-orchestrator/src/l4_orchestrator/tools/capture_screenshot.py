"""Capture the assigned Page once and save its viewport PNG through the caller."""
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
from time import perf_counter
from typing import Awaitable, Callable, Literal

from playwright.async_api import Error, TimeoutError as BrowserTimeoutError
from pydantic import Field, StrictBool

from ..page_state import PageState, PageStateError
from ..ports import ExecutionPort
from ..schemas import WireModel
from ..screenshot_storage import SavedScreenshot
from .schemas import ActionContext, page_target_error


class ScreenshotParams(WireModel):
    full_page: StrictBool = False


class CaptureScreenshotInput(WireModel):
    action_id: str = Field(min_length=1)
    tool: Literal["capture_screenshot"]
    target: None
    params: ScreenshotParams
    context: ActionContext


class CaptureScreenshotTool:
    def __init__(self, state: PageState, *, timeout_ms: int,
                 save_png: Callable[[bytes, dict], Awaitable[SavedScreenshot]]):
        if type(timeout_ms) is not int or timeout_ms < 1:
            raise ValueError("timeout_ms must be a positive integer")
        self.state, self.timeout_ms, self.save_png = state, timeout_ms, save_png

    def _observed_id(self):
        try:
            return self.state.read()["state_id"]
        except PageStateError:
            return None

    async def execute(self, arguments):
        request = CaptureScreenshotInput.model_validate(arguments)
        if error := page_target_error(request, self.state.page_id):
            return error
        started_at = datetime.now(timezone.utc).isoformat()
        started = perf_counter()
        before_id = None

        def response(status, data=None, error=None, after_id=None):
            return {
                "action_id": request.action_id, "tool": "capture_screenshot", "status": status,
                "started_at": started_at, "finished_at": datetime.now(timezone.utc).isoformat(),
                "duration_ms": round((perf_counter() - started) * 1000),
                "before_state_id": before_id, "after_state_id": after_id,
                "result": data, "observer_refs": {"l2": [], "l3": []}, "error": error,
            }

        def failure(code, message):
            return response("timeout" if code == "ACTION_TIMEOUT" else "failed", error={
                "code": code, "message": message,
                "recoverable": code not in {"PAGE_CLOSED", "BROWSER_CRASH"}})

        if request.params.full_page:
            return failure("UNSUPPORTED_CAPTURE", "Only viewport screenshots are supported in this increment.")
        page = self.state.page
        try:
            # An uncollected/invalid DOM observation must not block an unconditioned capture.
            if request.context.state_id is not None:
                before_id = self.state.read(request.context.state_id)["state_id"]
            else:
                try:
                    before_id = self.state.read()["state_id"]
                except PageStateError as exc:
                    if exc.code in {"PAGE_CLOSED", "BROWSER_CRASH"}:
                        raise
            png = await page.screenshot(type="png", full_page=False, timeout=self.timeout_ms,
                                        animations="allow", caret="initial")
            captured_at = datetime.now(timezone.utc).isoformat()
            if request.context.state_id is not None:
                self.state.read(request.context.state_id)
            captured_state_id = self._observed_id()
        except BrowserTimeoutError:
            return failure("ACTION_TIMEOUT", "Screenshot capture timed out; no image was saved.")
        except PageStateError as exc:
            return failure(exc.code, str(exc))
        except Error:
            code = "PAGE_CLOSED" if page.is_closed() else "INTERNAL_ERROR"
            try:
                self.state.read()
            except PageStateError as exc:
                if exc.code == "BROWSER_CRASH":
                    code = exc.code
            return failure(code, "The assigned page could not be captured.")

        metadata = {"action_id": request.action_id,
                    "context": request.context.model_dump(mode="json"),
                    "page_id": self.state.page_id, "captured_at": captured_at,
                    "capture_scope": "viewport", "before_state_id": before_id,
                    "capture_state_id": captured_state_id}
        try:
            saved = await self.save_png(png, metadata)
            if (not isinstance(saved, SavedScreenshot) or not saved.artifact_ref
                    or saved.sha256 != hashlib.sha256(png).hexdigest()):
                raise ValueError("The storage receipt did not identify the captured PNG")
        except Exception:
            return failure("ARTIFACT_SAVE_FAILED", "The screenshot could not be saved; no successful reference is available.")
        # Saving may await disk I/O while the page changes. Do not repeat an obsolete state ID.
        after_id = self._observed_id()
        if after_id != captured_state_id:
            after_id = None
        return response("success", {**asdict(saved), "target_type": "page", "captured": True,
                                    "page_id": self.state.page_id, "captured_at": captured_at},
                        after_id=after_id)

    def as_port(self):
        def prepare(request, assigned_task):
            return CaptureScreenshotInput.model_validate(request["arguments"]).model_dump(mode="json")

        return ExecutionPort(
            description="Capture the assigned Page's viewport once, save its PNG, and return capture metadata. The SDK connection delivers the saved PNG in the next model input without another capture.",
            kind="tool", provenance="new_observation",
            permission_description="Captures the supplied Page and calls the configured PNG saver. No navigation, automatic state refresh, AWS upload or retention decisions. The caller owns serial Page access and storage location.",
            prepare=prepare, invoke=self.execute,
        )
