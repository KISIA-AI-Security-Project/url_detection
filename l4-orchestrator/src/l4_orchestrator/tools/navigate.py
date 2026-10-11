"""One browser action. The caller owns the page, URL policy and session lifetime."""
from datetime import datetime, timezone
from time import perf_counter
from typing import Callable, Literal
from urllib.parse import urlsplit

from playwright.async_api import Error, Page, TimeoutError
from pydantic import Field

from ..ports import Authorization, ExecutionPort
from ..page_state import page_id_for
from ..schemas import WireModel
from .schemas import ActionContext, page_target_error


class NavigationTarget(WireModel):
    url: str = Field(min_length=1)


class NavigationParams(WireModel):
    wait_until: Literal["domcontentloaded", "load", "commit", "networkidle"] = "domcontentloaded"


class NavigateInput(WireModel):
    action_id: str = Field(min_length=1)
    tool: Literal["navigate"]
    target: NavigationTarget
    params: NavigationParams
    context: ActionContext


class NavigateTool:
    """No file storage, automatic retry, browser launch or session shutdown."""

    def __init__(self, page: Page, *, timeout_ms: int,
                 authorize_url: Callable[[str], Authorization]):
        if type(timeout_ms) is not int or timeout_ms < 1:
            raise ValueError("timeout_ms must be a positive integer")
        self.page = page
        self.timeout_ms = timeout_ms
        self.authorize_url = authorize_url

    async def execute(self, arguments):
        request = NavigateInput.model_validate(arguments)
        if error := page_target_error(request, page_id_for(self.page)):
            return error
        started_at = datetime.now(timezone.utc).isoformat()
        started = perf_counter()

        def result(status, data=None, error=None):
            return {
                "action_id": request.action_id, "tool": "navigate", "status": status,
                "started_at": started_at, "finished_at": datetime.now(timezone.utc).isoformat(),
                "duration_ms": round((perf_counter() - started) * 1000),
                "before_state_id": request.context.state_id, "after_state_id": None,
                "result": data, "observer_refs": {"l2": [], "l3": []}, "error": error,
            }

        def failure(status, code, message, recoverable):
            return result(status, error={"code": code, "message": message, "recoverable": recoverable})

        url = request.target.url
        try:
            parsed = urlsplit(url)
            valid = parsed.scheme in {"http", "https"} and bool(parsed.hostname)
            valid = valid and parsed.port != 0 and not any(c.isspace() or ord(c) < 32 for c in url)
            valid = valid and "\\" not in url
        except ValueError:
            valid = False
        if not valid:
            return failure("failed", "INVALID_URL", "An absolute HTTP/HTTPS URL is required.", True)

        permit = self.authorize_url(url)
        if not permit.allowed:
            return failure("blocked", "BLOCKED_URL", permit.reason, True)
        if self.page.is_closed():
            return failure("failed", "PAGE_CLOSED", "The supplied page is closed.", False)
        try:
            response = await self.page.goto(url, wait_until=request.params.wait_until, timeout=self.timeout_ms)
        except TimeoutError as exc:
            return failure("timeout", "NAVIGATION_TIMEOUT", str(exc), True)
        except Error as exc:
            code = "PAGE_CLOSED" if self.page.is_closed() else "INTERNAL_ERROR"
            return failure("failed", code, str(exc), not self.page.is_closed())

        return result("success", {
            "requested_url": url, "current_url": self.page.url,
            # 404/500 can still complete a browser navigation; preserve that distinction.
            "http_status": response.status if response is not None else None,
        })

    def as_port(self):
        def prepare(request, assigned_task):
            return NavigateInput.model_validate(request["arguments"]).model_dump(mode="json")

        return ExecutionPort(
            description="Navigate the supplied page and return requested URL, observed URL and HTTP status. No content analysis or evidence-file storage.",
            kind="tool", provenance="new_observation",
            permission_description="Checks the caller's initial-URL policy. Redirect/subresource network controls and serial page access belong to the caller's browser environment.",
            prepare=prepare, invoke=self.execute,
        )
