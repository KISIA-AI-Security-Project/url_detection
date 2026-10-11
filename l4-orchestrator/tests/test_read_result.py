from sdk_tool_checks import run_native_steps
"""Verify read behavior against injected snapshots, not an SDK Store."""
import asyncio
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from l4_orchestrator.ports import Authorization
from l4_orchestrator.tools.read_result import (
    ReadResultLookupError, ReadResultSource, ReadResultTool, ReadResultView,
)
from l4_orchestrator.tools.record_reader import RecordReader, RecordSource


JOB = "job-read-result"


class QueryFixture:
    """Only a test source: no persistence, SDK runtime or public Store API."""
    def __init__(self):
        self.calls = []
        self.works = {
            "W1": {"id": "W1", "job_id": JOB, "question": "현재 자료 확인",
                   "scope": {"target_refs": ["page:main"]}, "answer": None},
            "W2": {"id": "W2", "job_id": JOB, "question": "다른 자료 확인"},
        }
        self.tasks = {
            "T1": {"id": "T1", "work_id": "W1", "title": "페이지 열기",
                   "execution": {"kind": "tool", "name": "navigate"},
                   "status": "returned", "result_ref": "result:ACT1"},
            "T2": {"id": "T2", "work_id": "W1", "title": "화면 관찰",
                   "execution": {"kind": "agent", "instruction": "화면을 관찰한다"},
                   "status": "running", "result_ref": None},
            "T10": {"id": "T10", "work_id": "W1", "title": "추가 확인",
                    "execution": {"kind": "tool", "name": "record_reader"},
                    "status": "queued", "result_ref": None},
            "T3": {"id": "T3", "work_id": "W2", "title": "다른 업무",
                   "execution": {"kind": "tool", "name": "record_reader"},
                   "status": "returned", "result_ref": "result:ACT4"},
        }
        self.actions = [
            {"action_id": action_id, "work_id": work_id, "task_id": task_id,
             "tool_name": name, "status": status, "result_ref": ref,
             "started_at": started, "finished_at": finished, "error": error}
            for action_id, work_id, task_id, name, status, ref, started, finished, error in [
                ("ACT2", "W1", "T2", "get_page_state", "success", "result:ACT2", "s2", "f2", None),
                ("ACT3", "W1", "T2", "click", "failed", "result:ACT3", "s3", "f3", {"code": "NO_TARGET"}),
                ("ACT10", "W1", "T2", "wait_for", "preparing", None, None, None, None),
                ("ACT4", "W2", "T3", "record_reader", "success", "result:ACT4", "s4", "f4", None),
            ]
        ]
        self.results = {
            "result:ACT2": {"status": "success", "result": {"url": "https://example.test/",
                             "a/b": {"~key": [None, False, 0, "", []]}, "": "empty-key"}},
            "result:ACT3": {"status": "failed", "result": None, "error": {"code": "NO_TARGET"}},
            "report:T1": {"summary": "저장된 보고", "findings": [], "limits": []},
        }
        self.pending = {"result:ACT10", "report:T2"}
        self.cursors = {}

    def page(self, kind, identity, rows, limit, cursor):
        offset = 0
        if cursor is not None:
            entry = self.cursors.get(cursor)
            if entry is None or entry[:3] != (JOB, kind, identity):
                raise ReadResultLookupError("INVALID_CURSOR", "Cursor belongs to a different query.")
            offset = entry[3]
        selected = rows[offset:offset + limit]
        next_cursor = None
        if offset + len(selected) < len(rows):
            next_cursor = f"cursor-{len(self.cursors) + 1}"
            self.cursors[next_cursor] = (JOB, kind, identity, offset + len(selected))
        return selected, next_cursor

    async def read_work(self, identity, limit, cursor):
        self.calls.append(("work", identity, limit, cursor))
        if identity not in self.works:
            raise ReadResultLookupError("NOT_FOUND", "Work not registered.")
        rows = [row for row in self.tasks.values() if row["work_id"] == identity]
        rows.sort(key=lambda row: int(row["id"][1:]))
        # The source owns this projection. Agent instructions are in task lookup.
        summaries = [{key: value for key, value in row.items() if key != "execution"}
                     | {"execution": {key: value for key, value in row["execution"].items()
                                      if key in {"kind", "name"}}} for row in rows]
        rows, next_cursor = self.page("work", identity, summaries, limit, cursor)
        return ReadResultView(JOB, identity, {"work": self.works[identity], "tasks": rows}, next_cursor)

    async def read_task(self, identity, limit, cursor):
        self.calls.append(("task", identity, limit, cursor))
        if identity not in self.tasks:
            raise ReadResultLookupError("NOT_FOUND", "Task not registered.")
        rows = sorted([row for row in self.actions if row["task_id"] == identity],
                      key=lambda row: int(row["action_id"][3:]))
        rows, next_cursor = self.page("task", identity, rows, limit, cursor)
        return ReadResultView(JOB, identity, {"task": self.tasks[identity], "actions": rows}, next_cursor)

    async def read_result(self, ref):
        self.calls.append(("result", ref))
        if ref in self.pending:
            raise ReadResultLookupError("RESULT_NOT_READY", "Result is not yet saved.")
        if ref not in self.results:
            raise ReadResultLookupError("NOT_FOUND", "Result not registered.")
        return ReadResultView(JOB, ref, self.results[ref])

    def source(self):
        return ReadResultSource(JOB, self.read_work, self.read_task, self.read_result)


def tool(fixture=None, *, max_list_items=20, max_data_bytes=16000):
    fixture = fixture or QueryFixture()
    return ReadResultTool(fixture.source(), max_list_items=max_list_items,
                          max_data_bytes=max_data_bytes)


def read(reader, **arguments):
    return asyncio.run(reader.execute(arguments))


def test_lists_follow_work_task_relations_numeric_order_and_cursor_scope():
    fixture = QueryFixture()
    reader = tool(fixture)
    work = read(reader, kind="work", id="W1", limit=2)
    assert work["status"] == "ok" and work["data"]["work"]["answer"] is None
    assert [row["id"] for row in work["data"]["tasks"]] == ["T1", "T2"]
    assert "instruction" not in work["data"]["tasks"][1]["execution"]
    after = read(reader, kind="work", id="W1", limit=2, cursor=work["next_cursor"])
    assert [row["id"] for row in after["data"]["tasks"]] == ["T10"]
    assert after["next_cursor"] is None
    assert read(reader, kind="work", id="W2", limit=2,
                cursor=work["next_cursor"])["error"]["code"] == "INVALID_CURSOR"

    first = read(reader, kind="task", id="T2", limit=2)
    assert first["data"]["task"]["status"] == "running"
    assert first["data"]["task"]["result_ref"] is None
    assert [row["action_id"] for row in first["data"]["actions"]] == ["ACT2", "ACT3"]
    assert first["data"]["actions"][1]["error"] == {"code": "NO_TARGET"}
    fixture.tasks["T2"]["status"] = "returned"
    fixture.tasks["T2"]["result_ref"] = "report:T2"
    last = read(reader, kind="task", id="T2", limit=2, cursor=first["next_cursor"])
    assert last["data"]["task"]["status"] == "returned"
    assert [row["action_id"] for row in last["data"]["actions"]] == ["ACT10"]
    assert last["data"]["actions"][0]["status"] == "preparing"
    assert last["next_cursor"] is None
    assert read(reader, kind="task", id="T3", limit=2,
                cursor=first["next_cursor"])["error"]["code"] == "INVALID_CURSOR"
    assert not any("result" in row for row in first["data"]["actions"])


def test_exact_json_values_missing_and_pending_results_stay_distinct():
    fixture = QueryFixture()
    reader = tool(fixture)
    for index, value in enumerate([None, False, 0, "", []]):
        actual = read(reader, kind="result", id="result:ACT2",
                      pointer=f"/result/a~1b/~0key/{index}")
        assert actual["status"] == "ok" and actual["error"] is None
        assert actual["data"] == value and type(actual["data"]) is type(value)
    assert read(reader, kind="result", id="result:ACT2", pointer="/result/")["data"] == "empty-key"
    assert read(reader, kind="result", id="result:ACT2", pointer="/missing")["error"]["code"] == "VALUE_NOT_FOUND"
    for pointer in ["/result/a~1b/~0key/01", "/result/a~1b/~0key/-1"]:
        assert read(reader, kind="result", id="result:ACT2", pointer=pointer)["error"]["code"] == "VALUE_NOT_FOUND"
    pending = read(reader, kind="result", id="report:T2", pointer="")
    assert pending["error"]["code"] == "RESULT_NOT_READY" and pending["data"] is None
    assert read(reader, kind="result", id="result:ACT99", pointer="")["error"]["code"] == "NOT_FOUND"
    assert read(reader, kind="task", id="T99", limit=1)["error"]["code"] == "NOT_FOUND"
    report = read(reader, kind="result", id="report:T1", pointer="/summary")
    assert report["data"] == fixture.results["report:T1"]["summary"]
    failed = read(reader, kind="result", id="result:ACT3", pointer="")
    assert failed["status"] == "ok" and failed["data"] == fixture.results["result:ACT3"]
    assert failed["data"]["status"] == "failed"


def test_detached_returns_leave_store_bodies_and_refs_unchanged():
    fixture = QueryFixture()
    originals = deepcopy((fixture.works, fixture.tasks, fixture.actions, fixture.results))
    reader = tool(fixture)
    for args in [dict(kind="work", id="W1", limit=20),
                 dict(kind="task", id="T2", limit=20),
                 dict(kind="result", id="result:ACT2", pointer="")]:
        reply = read(reader, **args)
        reply["data"].clear()
    assert (fixture.works, fixture.tasks, fixture.actions, fixture.results) == originals
    assert len(fixture.calls) == 3


@pytest.mark.parametrize("arguments", [
    {"kind": "work", "id": "W0", "limit": 1},
    {"kind": "work", "id": "W01", "limit": 1},
    {"kind": "work", "id": "W1\n", "limit": 1},
    {"kind": "task", "id": "T2"},
    {"kind": "task", "id": "T2", "limit": True},
    {"kind": "task", "id": "T2", "limit": "2"},
    {"kind": "task", "id": "T2", "limit": 0},
    {"kind": "task", "id": "T2", "limit": 1, "pointer": ""},
    {"kind": "task", "id": "T2", "limit": 1, "cursor": ""},
    {"kind": "result", "id": "screenshot:captured-1", "pointer": ""},
    {"kind": "result", "id": "result:ACT2", "pointer": None},
    {"kind": "result", "id": "result:ACT2", "pointer": "", "limit": 1},
    {"kind": "result", "id": "result:ACT2", "pointer": "", "job_id": "another-job"},
    {"kind": "result", "id": "result:ACT2", "pointer": "", "path": "C:/another.json"},
])
def test_bad_inputs_never_invoke_the_query_source(arguments):
    fixture = QueryFixture()
    reader = tool(fixture)
    with pytest.raises(ValidationError):
        asyncio.run(reader.execute(arguments))
    with pytest.raises(ValidationError):
        reader.as_port().prepare({"arguments": arguments}, {})
    assert fixture.calls == []


def test_limits_and_invalid_pointers_do_not_fetch_or_silently_shorten_data():
    fixture = QueryFixture()
    reader = tool(fixture, max_list_items=1)
    limited = read(reader, kind="task", id="T2", limit=2)
    assert limited["error"]["code"] == "RETURN_LIMIT_EXCEEDED"
    for pointer in ["result/url", "/bad~", "/bad~2"]:
        assert read(reader, kind="result", id="result:ACT2", pointer=pointer)["error"]["code"] == "INVALID_POINTER"
    assert fixture.calls == []
    fixture.results["result:ACT2"] = "가"
    # UTF-8 JSON includes the quotes, so this is exactly five bytes.
    exact = tool(fixture, max_data_bytes=5)
    assert read(exact, kind="result", id="result:ACT2", pointer="")["data"] == "가"
    too_small = read(tool(fixture, max_data_bytes=4), kind="result", id="result:ACT2", pointer="")
    assert too_small["error"]["code"] == "VALUE_TOO_LARGE"
    assert too_small["data"] is None and too_small["next_cursor"] is None
    assert fixture.results["result:ACT2"] == "가"


@pytest.mark.parametrize("view", [
    ReadResultView("other-job", "T2", {"private": "must not leak"}),
    ReadResultView(JOB, "T3", {"private": "must not leak"}),
    ReadResultView(JOB, "T2", {"task": {"id": "T2", "work_id": "W1"}, "actions": [
        {"action_id": "ACT2", "work_id": "W2", "task_id": "T2"}]}),
    ReadResultView(JOB, "T2", {"task": {"id": "T2", "work_id": "W1"}, "actions": [
        {"action_id": "ACT10", "work_id": "W1", "task_id": "T2"},
        {"action_id": "ACT2", "work_id": "W1", "task_id": "T2"}]}),
    ReadResultView(JOB, "T2", {"task": {"id": "T2", "work_id": "W1"}, "actions": [
        {"action_id": "ACT2", "work_id": "W1", "task_id": "T2", "result": {"large": "body"}}]}),
    ReadResultView(JOB, "T2", {"task": {"id": "T2", "work_id": "W1"}, "actions": []}, "again"),
])
def test_inconsistent_list_views_never_return_data(view):
    async def wrong(*args):
        return view
    source = ReadResultSource(JOB, wrong, wrong, wrong)
    actual = read(ReadResultTool(source, max_list_items=2, max_data_bytes=16000),
                  kind="task", id="T2", limit=2)
    assert actual["error"]["code"] == "INVALID_SOURCE_REPLY"
    assert actual["data"] is None and actual["next_cursor"] is None


@pytest.mark.parametrize("body", [float("nan"), {1: "key"}, {"x": (1, 2)}, "\ud800"])
def test_invalid_selected_values_are_not_converted_to_json(body):
    fixture = QueryFixture()
    fixture.results["result:ACT2"] = body
    actual = read(tool(fixture), kind="result", id="result:ACT2", pointer="")
    assert actual["error"]["code"] == "INVALID_SOURCE_REPLY" and actual["data"] is None


def test_source_errors_and_cancellation_remain_errors_and_cancellation():
    async def unavailable(*args):
        raise RuntimeError("Do not expose internal paths or exception detail")
    source = ReadResultSource(JOB, unavailable, unavailable, unavailable)
    actual = read(ReadResultTool(source, max_list_items=1, max_data_bytes=1000),
                  kind="result", id="result:ACT2", pointer="")
    assert actual["error"]["code"] == "SOURCE_UNAVAILABLE"
    assert "internal paths" not in json.dumps(actual)

    async def cancellation():
        entered = asyncio.Event()
        calls = []
        async def blocked(*args):
            calls.append(args)
            entered.set()
            await asyncio.Event().wait()
        reader = ReadResultTool(ReadResultSource(JOB, blocked, blocked, blocked),
                                max_list_items=1, max_data_bytes=1000)
        pending = asyncio.create_task(reader.execute(
            {"kind": "result", "id": "result:ACT2", "pointer": ""}))
        await entered.wait()
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
        assert len(calls) == 1
    asyncio.run(cancellation())


def test_real_record_reader_return_through_sdk_and_following_manager_input():
    root = Path(__file__).resolve().parents[2]
    ref = "records/a5091407d4c2c2f5b8cb95a3acc6ee59/1/l3/l3.json"
    path = root / "docs/l4-first-investigation-20260928/sources/s3" / ref
    original = path.read_bytes()
    sha = hashlib.sha256(original).hexdigest()
    native = RecordReader({ref: RecordSource(path, sha)}, max_data_bytes=4096).read({
        "record_ref": ref, "pointer": "/observation/raw/html/document"})
    assert native["status"] == "ok"
    fixture = QueryFixture()
    fixture.results["result:ACT2"] = native
    source_snapshot = deepcopy(fixture.results)
    proof = asyncio.run(run_native_steps({"read_result": tool(fixture)}, [("read_result", {
        "kind": "result", "id": "result:ACT2", "pointer": "/data"})]))
    expected = {"status": "ok", "job_id": JOB, "kind": "result", "id": "result:ACT2",
                "pointer": "/data", "data": native["data"], "next_cursor": None, "error": None}
    assert proof.results == [expected] and "source" not in expected["data"]
    assert fixture.results == source_snapshot and path.read_bytes() == original
    assert fixture.calls == [("result", "result:ACT2")]
