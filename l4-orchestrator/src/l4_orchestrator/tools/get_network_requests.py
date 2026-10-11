"""Query collected network summaries and registered detail references."""
from datetime import datetime, timezone
from time import perf_counter
from typing import Literal

from pydantic import Field, model_validator

from ..network_capture import NetworkCapture
from ..ports import ExecutionPort
from ..schemas import WireModel
from .schemas import ActionContext, page_target_error


class NetworkQueryParams(WireModel):
    capture_id: str | None = Field(default=None, min_length=1)
    after_sequence: int = Field(default=0, strict=True, ge=0)
    limit: int = Field(strict=True, ge=1)

    @model_validator(mode="after")
    def cursor_has_capture(self):
        if self.after_sequence > 0 and self.capture_id is None:
            raise ValueError("An incremental cursor requires its capture_id")
        return self


class GetNetworkRequestsInput(WireModel):
    action_id: str = Field(min_length=1)
    tool: Literal["get_network_requests"]
    target: None
    params: NetworkQueryParams
    context: ActionContext

    @model_validator(mode="after")
    def independent_of_dom_state(self):
        if self.context.state_id is not None:
            raise ValueError("Network queries require state_id=null; use capture_id/after_sequence instead")
        return self


class GetNetworkRequestsTool:
    def __init__(self, capture: NetworkCapture, *, max_return_items: int):
        if type(max_return_items) is not int or max_return_items < 1:
            raise ValueError("max_return_items must be positive")
        self.capture, self.max_return_items = capture, max_return_items

    async def execute(self, arguments):
        request = GetNetworkRequestsInput.model_validate(arguments)
        if error := page_target_error(request, self.capture.state.page_id):
            return error
        started_at, started = datetime.now(timezone.utc).isoformat(), perf_counter()
        data, error, status = None, None, "success"
        try:
            if request.params.limit > self.max_return_items:
                raise ValueError("RETURN_LIMIT_EXCEEDED")
            data = self.capture.snapshot(**request.params.model_dump())
        except ValueError as exc:
            code = str(exc)
            status = "blocked" if code == "RETURN_LIMIT_EXCEEDED" else "failed"
            error = {"code": code, "message": "Check the requested limit and capture cursor. No new request was sent.", "recoverable": True}
        return {"action_id": request.action_id, "tool": "get_network_requests", "status": status,
                "started_at": started_at, "finished_at": datetime.now(timezone.utc).isoformat(),
                "duration_ms": round((perf_counter() - started) * 1000),
                "before_state_id": None, "after_state_id": None,
                "result": data, "observer_refs": {"l2": [], "l3": []}, "error": error}

    def as_port(self):
        def prepare(request, assigned_task):
            return GetNetworkRequestsInput.model_validate(request["arguments"]).model_dump(mode="json")
        return ExecutionPort(
            description="Read bounded HTTP request summaries from the assigned Page's existing capture. params.limit is required. First query uses after_sequence=0; incremental queries provide capture_id and the returned next_after_sequence. Later changes repeat the same request_id with a newer sequence. detail_state=saved includes a registered record_ref for read_record; no raw bodies appear in this list.",
            kind="tool", provenance="existing_material",
            permission_description="Reads captured Page HTTP events without browser input, new HTTP requests, DOM observation, reset, file duplication or interpretation. Queries remain available after the Page closes. Capture must be attached before actions; its limits, body selection, saver and lifecycle belong to the caller. Record references are returned only after the saver completes.",
            prepare=prepare, invoke=self.execute)
