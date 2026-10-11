"""Export one current main-document DOM as an HTML file through the caller."""
import asyncio
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
from time import perf_counter
from typing import Awaitable, Callable, Literal

from playwright.async_api import Error
from pydantic import Field

from ..page_export_storage import HTML_CONTENT_TYPE, SavedPageExport
from ..page_state import PageState, PageStateError
from ..ports import ExecutionPort
from ..schemas import WireModel
from .schemas import ActionContext, page_target_error


_COLLECT = """() => {
    const root = document.documentElement;
    return {
        is_html: root.namespaceURI === "http://www.w3.org/1999/xhtml",
        html: root.outerHTML,
        doctype: document.doctype ? new XMLSerializer().serializeToString(document.doctype) : "",
        url: location.href, observed_at: new Date().toISOString()
    };
}"""


class ExportPageParams(WireModel):
    pass


class ExportPageInput(WireModel):
    action_id: str = Field(min_length=1)
    tool: Literal["export_page"]
    target: None
    params: ExportPageParams
    context: ActionContext


class ExportPageTool:
    def __init__(self, state: PageState, *, timeout_ms: int, max_html_bytes: int,
                 save_html: Callable[[bytes, dict], Awaitable[SavedPageExport]]):
        for name, value in (("timeout_ms", timeout_ms), ("max_html_bytes", max_html_bytes)):
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if not callable(save_html):
            raise TypeError("The caller must provide an HTML saving function")
        self.state, self.timeout_ms = state, timeout_ms
        self.max_html_bytes, self.save_html = max_html_bytes, save_html

    async def _collect(self, request):
        snapshot = None
        try:
            snapshot = await self.state.observe(request.context.state_id)
            observed = await self.state.page.evaluate(_COLLECT)
            self.state.read(snapshot["state_id"])
            if not observed["is_html"]:
                raise PageStateError("UNSUPPORTED_DOCUMENT", "The assigned document is not an HTML document.")
            # PageState fingerprints outerHTML, without a doctype.
            fingerprint = "sha256:" + hashlib.sha256(observed["html"].encode("utf-8")).hexdigest()
            if observed["url"] != snapshot["url"] or fingerprint != snapshot["dom_fingerprint"]:
                self.state.invalidate()
                raise PageStateError("STATE_CHANGED", "The page changed while collecting its HTML.")
            raw = (observed["doctype"] + observed["html"]).encode("utf-8")
            if len(raw) > self.max_html_bytes:
                raise PageStateError("HTML_TOO_LARGE", "The complete HTML exceeds the caller's file limit; nothing was saved.")
            return raw, {
                "page_id": snapshot["page_id"], "state_id": snapshot["state_id"],
                "url": observed["url"], "observed_at": observed["observed_at"],
                "observation_scope": "main_document_light_dom",
            }
        except Error as exc:
            self.state._check_page()
            if snapshot is not None:
                self.state.read(snapshot["state_id"])
            raise PageStateError("INTERNAL_ERROR", "The assigned page HTML could not be read.") from exc
        except UnicodeError as exc:
            raise PageStateError("INVALID_PAGE_TEXT", "The page HTML cannot be encoded as UTF-8.") from exc

    async def execute(self, arguments):
        request = ExportPageInput.model_validate(arguments)
        if error := page_target_error(request, self.state.page_id):
            return error
        started_at = datetime.now(timezone.utc).isoformat()
        started = perf_counter()

        def response(status, data=None, error=None, after_id=None):
            return {
                "action_id": request.action_id, "tool": "export_page", "status": status,
                "started_at": started_at, "finished_at": datetime.now(timezone.utc).isoformat(),
                "duration_ms": round((perf_counter() - started) * 1000),
                "before_state_id": request.context.state_id if data is not None else None,
                "after_state_id": after_id, "result": data,
                "observer_refs": {"l2": [], "l3": []}, "error": error,
            }

        def failure(code, message):
            return response("timeout" if code == "ACTION_TIMEOUT" else "failed", error={
                "code": code, "message": message,
                "recoverable": code not in {"PAGE_CLOSED", "BROWSER_CRASH"},
            })

        try:
            try:
                raw, observed = await asyncio.wait_for(self._collect(request), self.timeout_ms / 1000)
            except TimeoutError as exc:
                self.state._check_page()
                raise PageStateError("ACTION_TIMEOUT", "HTML collection timed out; no file was saved.") from exc
        except PageStateError as exc:
            return failure(exc.code, str(exc))

        try:
            saved = await self.save_html(raw, {
                "action_id": request.action_id, "context": request.context.model_dump(mode="json"),
                **observed,
            })
            if (not isinstance(saved, SavedPageExport) or not saved.file_ref
                    or saved.size_bytes != len(raw) or saved.sha256 != hashlib.sha256(raw).hexdigest()
                    or not isinstance(saved.relative_path, str) or not saved.relative_path
                    or saved.relative_path in {".", ".."}
                    or any(c in saved.relative_path for c in "/\\:\0")):
                raise ValueError("The storage receipt did not identify the complete HTML file")
        except Exception:
            return failure("ARTIFACT_SAVE_FAILED", "The HTML save was not confirmed; no successful file reference is available.")

        after_id = None
        try:
            after_id = self.state.read(observed["state_id"])["state_id"]
        except PageStateError:
            pass  # The completed file still describes its recorded observation.
        return response("success", {**asdict(saved), "content_type": HTML_CONTENT_TYPE, **observed},
                        after_id=after_id)

    def as_port(self):
        def prepare(request, assigned_task):
            return ExportPageInput.model_validate(request["arguments"]).model_dump(mode="json")

        return ExecutionPort(
            description="Save the current main-document DOM as one complete UTF-8 HTML file, including "
                        "its doctype. Null state_id observes now; an explicit ID must still match. "
                        "Returns a file reference and a path relative to the supplied Bash work directory, "
                        "not the HTML body. This is DOM serialization, not the original HTTP response, "
                        "live JavaScript memory or a bundle of external resources.",
            kind="tool", provenance="new_observation",
            permission_description="Reads the assigned Page and calls the configured HTML saver only "
                                   "when requested. The caller supplies limits and the shared export/Bash "
                                   "directory, serial Page access, file publication and retention.",
            prepare=prepare, invoke=self.execute,
        )
