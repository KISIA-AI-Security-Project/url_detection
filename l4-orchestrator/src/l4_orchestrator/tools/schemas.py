"""Context carried by browser action requests."""
from datetime import datetime, timezone

from pydantic import Field

from ..schemas import WireModel


class ActionContext(WireModel):
    job_id: str = Field(min_length=1)
    scenario_id: str = Field(min_length=1)
    step_id: str = Field(min_length=1)
    state_id: str | None
    page_id: str | None = Field(default=None, min_length=1, exclude_if=lambda value: value is None,
        description="Page ID from get_page_state. Omit/null uses the caller's fixed default Page; it never selects the last-used tab.")


def page_failure(arguments: dict, code: str, message: str) -> dict:
    """A rejected page selection has performed no browser operation."""
    now = datetime.now(timezone.utc).isoformat()
    return {"action_id": arguments["action_id"], "tool": arguments["tool"], "status": "failed",
            "started_at": now, "finished_at": now, "duration_ms": 0,
            "before_state_id": None, "after_state_id": None, "result": None,
            "observer_refs": {"l2": [], "l3": []},
            "error": {"code": code, "message": message, "recoverable": True}}


def page_target_error(request, actual_page_id: str) -> dict | None:
    """Even an unwrapped single-Page Tool must not ignore another page_id."""
    if request.context.page_id not in (None, actual_page_id):
        return page_failure(request.model_dump(mode="json"), "PAGE_MISMATCH",
                            "This Tool is bound to a different Page. Use the caller's page routing connection.")
    return None
