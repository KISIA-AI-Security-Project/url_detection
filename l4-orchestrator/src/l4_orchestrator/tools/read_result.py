"""Read caller-provided L4 views and exact parts of saved results.

The source owns Store lookup, authorization and cursor allocation. This Tool
does not own a Store, create actions, save results, open files or publish to AWS.
"""
from copy import deepcopy
from dataclasses import dataclass
import json
import math
import re
from typing import Annotated, Awaitable, Callable, Literal

from pydantic import Field, JsonValue, TypeAdapter

from ..ports import ExecutionPort
from ..schemas import WireModel
from .record_reader import _select


class ReadWorkInput(WireModel):
    kind: Literal["work"]
    id: str = Field(strict=True, pattern=r"^W[1-9][0-9]*$")
    limit: int = Field(strict=True, ge=1)
    cursor: str | None = Field(default=None, strict=True, min_length=1)


class ReadTaskInput(WireModel):
    kind: Literal["task"]
    id: str = Field(strict=True, pattern=r"^T[1-9][0-9]*$")
    limit: int = Field(strict=True, ge=1)
    cursor: str | None = Field(default=None, strict=True, min_length=1)


class ReadSavedResultInput(WireModel):
    kind: Literal["result"]
    id: str = Field(strict=True, pattern=r"^(result:ACT|report:T)[1-9][0-9]*$")
    pointer: str = Field(strict=True)


ReadResultInput = Annotated[
    ReadWorkInput | ReadTaskInput | ReadSavedResultInput,
    Field(discriminator="kind"),
]
_INPUT = TypeAdapter(ReadResultInput)


@dataclass(frozen=True)
class ReadResultView:
    """One coherent caller snapshot; data is a view or a complete saved body.

    work: {"work": {...}, "tasks": [task summaries]}
    task: {"task": {...}, "actions": [action summaries]}
    result: the original Tool return or Agent report, without an extra wrapper.
    The caller binds/validates next_cursor against this job, kind and id.
    """
    job_id: str
    id: str
    data: JsonValue
    next_cursor: str | None = None


@dataclass(frozen=True)
class ReadResultSource:
    """Trusted query callbacks bound to one job and the caller's read scope.

    read_work/read_task receive (id, limit, cursor). read_result receives a ref.
    Callbacks return ReadResultView or raise ReadResultLookupError. They must
    provide list items in increasing numeric T/ACT order, without raw bodies.
    No SDK Store method names or internal dictionaries are imposed here.
    """
    job_id: str
    read_work: Callable[[str, int, str | None], Awaitable[ReadResultView]]
    read_task: Callable[[str, int, str | None], Awaitable[ReadResultView]]
    read_result: Callable[[str], Awaitable[ReadResultView]]


class ReadResultLookupError(Exception):
    """A known lookup outcome reported by the caller's Store adapter."""
    def __init__(self, code: str, message: str):
        if code not in {"NOT_FOUND", "RESULT_NOT_READY", "INVALID_CURSOR", "FORBIDDEN"}:
            raise ValueError("Unsupported lookup error code")
        if type(message) is not str or not message:
            raise ValueError("A lookup error requires a message")
        message.encode("utf-8")
        super().__init__(message)
        self.code, self.message = code, message


def _json_copy(value):
    """Copy plain JSON without coercing keys, tuples, booleans or numbers."""
    ancestors = set()

    def check(item):
        if item is None or type(item) in (str, bool, int):
            return
        if type(item) is float:
            if not math.isfinite(item):
                raise ValueError("Nonfinite number")
            return
        if type(item) not in (dict, list):
            raise ValueError("Non-JSON value")
        identity = id(item)
        if identity in ancestors:
            raise ValueError("Cyclic value")
        ancestors.add(identity)
        if type(item) is dict:
            if any(type(key) is not str for key in item):
                raise ValueError("Non-string JSON key")
            children = item.values()
        else:
            children = item
        for child in children:
            check(child)
        ancestors.remove(identity)

    check(value)
    copied = deepcopy(value)
    encoded = json.dumps(copied, ensure_ascii=False, allow_nan=False,
                         separators=(",", ":")).encode("utf-8")
    return copied, len(encoded)


def _number(value, prefix):
    if type(value) is not str or not re.fullmatch(prefix + r"[1-9][0-9]*", value):
        raise ValueError("Invalid source ID")
    return int(value[len(prefix):])


class ReadResultTool:
    def __init__(self, source: ReadResultSource, *, max_list_items: int,
                 max_data_bytes: int):
        if not isinstance(source, ReadResultSource):
            raise ValueError("A caller-provided ReadResultSource is required")
        if type(source.job_id) is not str or not source.job_id:
            raise ValueError("The source requires its job_id")
        source.job_id.encode("utf-8")
        if not all(callable(fn) for fn in
                   (source.read_work, source.read_task, source.read_result)):
            raise ValueError("All source queries must be callable")
        for value in (max_list_items, max_data_bytes):
            if type(value) is not int or value < 1:
                raise ValueError("Caller limits must be positive integers")
        self._source = source
        self._max_list_items = max_list_items
        self._max_data_bytes = max_data_bytes

    def _check_view(self, request, view):
        if not isinstance(view, ReadResultView):
            raise ValueError("The query did not return a ReadResultView")
        if view.job_id != self._source.job_id or view.id != request.id:
            raise ValueError("Source job or target mismatch")
        cursor = view.next_cursor
        if cursor is not None and (type(cursor) is not str or not cursor):
            raise ValueError("Invalid source cursor")
        if cursor is not None:
            cursor.encode("utf-8")
        if request.kind == "result":
            if cursor is not None:
                raise ValueError("A body lookup cannot return a list cursor")
            return

        entity_key, list_key, prefix = (
            ("work", "tasks", "T") if request.kind == "work"
            else ("task", "actions", "ACT")
        )
        data = view.data
        if type(data) is not dict or set(data) != {entity_key, list_key}:
            raise ValueError("Invalid list view shape")
        entity, items = data[entity_key], data[list_key]
        if type(entity) is not dict or entity.get("id") != request.id:
            raise ValueError("Source entity mismatch")
        if "job_id" in entity and entity["job_id"] != self._source.job_id:
            raise ValueError("Source entity job mismatch")
        if type(items) is not list or len(items) > request.limit:
            raise ValueError("Source returned more than the requested list limit")
        if cursor is not None and (not items or cursor == request.cursor):
            raise ValueError("Source cursor makes no progress")
        if request.kind == "task":
            _number(entity.get("work_id"), "W")
        previous = 0
        for item in items:
            if type(item) is not dict:
                raise ValueError("Invalid list item")
            identity_key = "id" if request.kind == "work" else "action_id"
            number = _number(item.get(identity_key), prefix)
            if number <= previous:
                raise ValueError("List items are duplicated or not in numeric order")
            previous = number
            if "job_id" in item and item["job_id"] != self._source.job_id:
                raise ValueError("List item job mismatch")
            if request.kind == "work":
                if item.get("work_id") != request.id:
                    raise ValueError("Task belongs to another work")
            elif (item.get("task_id") != request.id or
                  item.get("work_id") != entity["work_id"]):
                raise ValueError("Action belongs to another task or work")
            if "result" in item or "data" in item or "body" in item:
                raise ValueError("Raw result bodies do not belong in list items")

    async def execute(self, arguments):
        request = _INPUT.validate_python(arguments)
        reply = {"status": "error", "job_id": self._source.job_id,
                 "kind": request.kind, "id": request.id,
                 "pointer": request.pointer if request.kind == "result" else None,
                 "data": None, "next_cursor": None, "error": None}

        def fail(code, message):
            reply["error"] = {"code": code, "message": message}
            return reply

        if request.kind == "result":
            if request.pointer != "" and (
                not request.pointer.startswith("/") or
                re.search(r"~(?![01])", request.pointer)
            ):
                return fail("INVALID_POINTER", "Use an empty string or a valid JSON Pointer.")
        elif request.limit > self._max_list_items:
            return fail("RETURN_LIMIT_EXCEEDED", "Request a list limit within the caller's configured maximum.")
        try:
            if request.kind == "work":
                view = await self._source.read_work(request.id, request.limit, request.cursor)
            elif request.kind == "task":
                view = await self._source.read_task(request.id, request.limit, request.cursor)
            else:
                view = await self._source.read_result(request.id)
        except ReadResultLookupError as exc:
            return fail(exc.code, exc.message)
        except Exception:
            return fail("SOURCE_UNAVAILABLE", "The provided Store query could not be completed.")

        try:
            self._check_view(request, view)
        except (ValueError, TypeError, RecursionError):
            return fail("INVALID_SOURCE_REPLY", "The Store query returned an inconsistent view; no data was returned.")
        try:
            data = _select(view.data, request.pointer) if request.kind == "result" else view.data
        except ValueError:
            return fail("INVALID_POINTER", "Use an empty string or a valid JSON Pointer.")
        except (KeyError, IndexError):
            return fail("VALUE_NOT_FOUND", "The requested JSON value is absent; it was not an empty result.")
        try:
            copied, size = _json_copy(data)
        except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
            return fail("INVALID_SOURCE_REPLY", "The selected data is not plain UTF-8 JSON; no values were converted.")
        if size > self._max_data_bytes:
            return fail("VALUE_TOO_LARGE", "Request fewer list items or a smaller JSON value; no data was truncated.")
        reply.update(status="ok", data=copied, next_cursor=view.next_cursor)
        return reply

    def as_port(self):
        def prepare(request, assigned_task):
            return _INPUT.validate_python(request["arguments"]).model_dump(mode="json")

        return ExecutionPort(
            description="Read L4 work/task lists or one exact JSON value from a saved Tool result or Agent report. kind=work/task requires id and limit; cursor continues the same list. kind=result requires a result:ACTn or report:Tn reference and pointer (empty selects its whole body). Returns existing references, not all action bodies.",
            kind="tool", provenance="existing_material",
            permission_description="Reads a caller-provided query source for one job and its allowed scope. No model-selected job, path or AWS location. Source adapters own authorization/cursors; runtime wrappers own action and progress recording. Performs no new observation, persistence or result interpretation.",
            prepare=prepare, invoke=self.execute,
        )
