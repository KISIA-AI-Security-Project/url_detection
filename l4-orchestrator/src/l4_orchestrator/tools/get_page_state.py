"""One page query: basic state plus only the requested text, links or controls."""
import asyncio
from datetime import datetime, timezone
from time import perf_counter
from typing import Literal

from playwright.async_api import Error
from pydantic import Field, StrictBool, model_serializer, model_validator

from ..elements import ElementRegistry
from ..page_content import PageContentReader
from ..page_state import PageState, PageStateError, page_id_for
from ..ports import ExecutionPort
from ..schemas import WireModel
from .schemas import ActionContext, page_target_error


class PageStateParams(WireModel):
    scope: Literal["page", "pages"] = Field(default="page",
        description="page observes one Page; pages lists open tabs in the same BrowserContext without refreshing their DOM states.")
    include: tuple[Literal["text", "links", "elements"], ...] = Field(
        default=(), max_length=3,
        description="Additional information to collect with the basic page state. Empty means state only. Select text, links and/or elements; each at most once.")
    visible_only: StrictBool = Field(default=True,
        description="Filter elements to visible controls; applies only when include contains elements. Does not change the text/link collection rules.")

    @model_validator(mode="after")
    def selected_information(self):
        if len(set(self.include)) != len(self.include):
            raise ValueError("include must not contain duplicates")
        if self.scope == "pages" and self.include:
            raise ValueError("Listing pages cannot include text, links or elements")
        if not self.visible_only and "elements" not in self.include:
            raise ValueError("visible_only=false requires include to contain elements")
        return self

    @model_serializer(mode="wrap")
    def supplied_params(self, handler):
        # Keep the existing params={} form while retaining explicit defaults in
        # prepared input (e.g. include=[] or visible_only=true) exactly as supplied.
        return {name: value for name, value in handler(self).items() if name in self.model_fields_set}


class GetPageStateInput(WireModel):
    action_id: str = Field(min_length=1)
    tool: Literal["get_page_state"]
    target: None
    params: PageStateParams
    context: ActionContext

    @model_validator(mode="after")
    def page_list_is_not_a_dom_observation(self):
        if self.params.scope == "pages" and (self.context.page_id is not None or self.context.state_id is not None):
            raise ValueError("Listing pages requires page_id and state_id to be null or omitted")
        return self


class GetPageStateTool:
    def __init__(self, state: PageState, *, elements: ElementRegistry, content: PageContentReader):
        if elements.state is not state or content.state is not state:
            raise ValueError("Page query collectors must share the same PageState")
        self.state = state
        self.elements = elements
        self.content = content

    async def _read_page(self, request):
        include = request.params.include
        controls = "elements" in include
        complete = False
        if controls:
            # Also discard an old list if an earlier text read or state read fails.
            self.elements.discard_query()
        try:
            data = await self.state.observe(request.context.state_id)
            state_id = data["state_id"]
            if "text" in include or "links" in include:
                kind = "both" if "text" in include and "links" in include else (
                    "text" if "text" in include else "links")
                data.update(await self.content.read(kind=kind, expected_state_id=state_id))
            if controls:
                found = await self.elements.query(
                    visible_only=request.params.visible_only, expected_state_id=state_id)
                data.update(elements=found["elements"], observed_at=found["observed_at"])
            # One ID is a shared observation baseline, not an atomic pixel snapshot.
            # A change during either collector must not produce mixed successful data.
            self.state.read(state_id)
            complete = True
            return data
        finally:
            if controls and not complete:
                self.elements.discard_query()

    async def _list_pages(self):
        async def describe(page):
            row = {"page_id": page_id_for(page), "url": page.url, "title": None, "error": None}
            try:
                row["title"] = await asyncio.wait_for(page.title(), self.state.timeout_ms / 1000)
            except TimeoutError:
                row["error"] = {"code": "ACTION_TIMEOUT", "message": "The title read timed out."}
            except Error:
                row["error"] = {"code": "PAGE_CLOSED" if page.is_closed() else "INTERNAL_ERROR",
                                "message": "The title could not be read; the page may have changed."}
            return row

        pages = [page for page in self.state.page.context.pages if not page.is_closed()]
        return {"pages": await asyncio.gather(*(describe(page) for page in pages)),
                "default_page_id": self.state.page_id,
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "observation_scope": "browser_context_open_pages"}

    async def execute(self, arguments):
        request = GetPageStateInput.model_validate(arguments)
        if error := page_target_error(request, self.state.page_id):
            return error
        started_at = datetime.now(timezone.utc).isoformat()
        started = perf_counter()
        data, error = None, None
        status = "success"
        try:
            data = (await self._list_pages() if request.params.scope == "pages"
                    else await self._read_page(request))
        except PageStateError as exc:
            status = "timeout" if exc.code == "ACTION_TIMEOUT" else "failed"
            error = {"code": exc.code, "message": str(exc),
                     "recoverable": exc.code not in {"PAGE_CLOSED", "BROWSER_CRASH"}}
        state_id = data.get("state_id") if data is not None else None
        return {
            "action_id": request.action_id, "tool": "get_page_state", "status": status,
            "started_at": started_at, "finished_at": datetime.now(timezone.utc).isoformat(),
            "duration_ms": round((perf_counter() - started) * 1000),
            "before_state_id": request.context.state_id if data is not None else None,
            "after_state_id": state_id,
            "result": data, "observer_refs": {"l2": [], "l3": []}, "error": error,
        }

    def as_port(self):
        def prepare(request, assigned_task):
            return GetPageStateInput.model_validate(request["arguments"]).model_dump(mode="json")

        return ExecutionPort(
            description="Read basic page state and only the extra information selected by params.include: text, links and/or elements. Empty include reads basic state only. Text is bounded main-document innerText, including off-viewport text, not OCR. Links return HTML href and resolved_url, not final destinations; text and links have independent truncation flags. Elements return original-node IDs, role, accessible name, text, visible/enabled; native selects include options and checkboxes/radios include checked state. visible_only filters elements only. Use this returned page_id/state_id and element_id for actions. context.state_id=null collects one new state; an explicit ID must remain valid. Default scope=page reads context.page_id (omit/null for the fixed default Page). scope=pages with empty include and null page_id/state_id lists open tabs without refreshing DOM states. No reload, screenshot, interpretation or file storage.",
            kind="tool", provenance="new_observation",
            permission_description="One page-information read permission covers basic state, text, links and controls. Requested extras read the supplied live Page against the same state_id. The caller supplies the shared collectors, content limits, serial page access and session lifetime.",
            prepare=prepare, invoke=self.execute,
        )
