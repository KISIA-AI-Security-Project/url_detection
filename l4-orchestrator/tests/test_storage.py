import asyncio
import hashlib
from dataclasses import replace

import pytest

from examples.storage_memory_io import MemoryStorageIO
from l4_orchestrator.execution_control import AssignmentError, ExecutionEnded, StoreError
from l4_orchestrator.json_values import loads, same_json
from l4_orchestrator.sdk_types import ManagerTurn
from l4_orchestrator.storage import L4Store, CompletedFile, DuplicateJobError, PublisherError
from l4_orchestrator.storage.aws_codec import AwsStorageConfig, AwsCodec, item_size_bound, plain_item
from l4_orchestrator.storage.aws_publisher import AwsPublisher
from l4_orchestrator.storage.aws_reader import AwsRecordReader
from l4_orchestrator.storage.models import Record, Publication
from l4_orchestrator.storage.read_result_source import make_read_result_source
from l4_orchestrator.tools.read_result import ReadResultTool


CONFIG = AwsStorageConfig("ap-northeast-2", "test-l4", "test-evidence", retry_seconds=0.001)
REPORT = {"summary": "확인한 범위", "findings": [], "limits": ["관측만 기록"]}


def decision(count=2):
    return {"summary": "자료를 확인한다", "new_works": [
        {"id": "W1", "title": "자료 확인", "question": "무엇이 기록됐는가", "reason": "확인 필요",
         "scope": {"target_refs": ["record:existing"], "allowed_tools": ["record_reader"], "restrictions": []}}],
        "tasks": [{"id": f"T{i}", "work_id": "W1", "title": f"자료 {i}", "after": [],
                   "execution": {"kind": "agent", "instruction": "자료 확인", "allowed_tools": ["record_reader"],
                                 "input_refs": ["record:existing"]}} for i in range(1, count + 1)],
        "review_after": {"tasks": ["T1"], "when": "all"}, "work_answers": [], "finish": None}


async def assign(store, data=None, call="M1"):
    data = data or decision()
    await store.start_manager_call(call, [])
    store.accept_manager_run(call, history=[{"role": "user", "content": "원본"}], delivered_refs=[], decision=data)
    await store.save_assignment(call, data)
    return data


async def finish(store):
    store.end_execution()
    for identity in store._task_keys:
        if not store.task_has_ended(identity):
            await store.finish_task(identity, "ended_by_manager")
    await store.save_final(REPORT)
    store.seal_records()


def test_atomic_assignment_retry_and_failed_validation():
    async def case():
        store = L4Store("assignment")
        data = await assign(store)
        before = (store.snapshot_records(), store.pending_count, store.next_assignment_ids())
        assert await store.save_assignment("M1", data) is False
        assert before == (store.snapshot_records(), store.pending_count, store.next_assignment_ids())
        data["tasks"][0]["title"] = "mutated caller"
        assert (await store.read_task("T1"))["title"] == "자료 1"
        invalid = decision(2)
        invalid["new_works"][0]["id"] = "W2"
        for index, task in enumerate(invalid["tasks"], 3):
            task.update(id=f"T{index}", work_id="W2")
        invalid["tasks"][-1]["work_id"] = "W99"
        invalid["review_after"]["tasks"] = ["T3"]
        await store.start_manager_call("M2", [])
        store.accept_manager_run("M2", history=[], delivered_refs=[], decision=invalid)
        before = (store.snapshot_records(), store.pending_count, store.next_assignment_ids())
        with pytest.raises(AssignmentError):
            await store.save_assignment("M2", invalid)
        assert before == (store.snapshot_records(), store.pending_count, store.next_assignment_ids())
        assert "W2" not in [r.body().get("id") for r in store.snapshot_records() if r.record_key.startswith("WORK#")]
    asyncio.run(case())


def test_parallel_actions_copy_exact_native_and_result_scope():
    async def case():
        store = L4Store("parallel")
        await assign(store)
        await store.start_task("T1")
        await store.start_task("T2")
        ids = await asyncio.gather(*(store.create_action("W1", f"T{i%2+1}", "record_reader", "{}") for i in range(20)))
        assert ids == [f"ACT{i}" for i in range(1, 21)]
        native = {"status": "ok", "data": {"a/b": [False, None, 0, "", [], {"한글": "원본"}]}}
        await store.start_action("ACT1", {"path": "/a/b", "context": {"state_id": None}})
        ref = await store.finish_action("ACT1", native)
        native["data"]["a/b"][-1]["한글"] = "changed"
        value = await store.read_result(ref)
        assert value["data"]["a/b"][-1]["한글"] == "원본"
        value["data"] = None
        assert (await store.read_result(ref))["data"] is not None
        with pytest.raises(StoreError):
            await store.finish_action("ACT1", native)
        # Agent tasks cannot use an internal ACT as their final task report.
        with pytest.raises(StoreError):
            await store.finish_task("T2", "success", ref)
        original = REPORT | {"findings": [{"statement": "missing", "refs": ["result:ACT999"]}]}
        report_ref = await store.save_report("T2", original)
        saved = await store.read_result(report_ref)
        assert saved["findings"] == original["findings"]
        assert saved["reference_errors"] == [{"ref": "result:ACT999",
            "reason": "No saved result exists for this reference"}]
    asyncio.run(case())


def test_manager_snapshot_late_result_and_registration_rejection():
    async def case():
        store = L4Store("late")
        await assign(store)
        for task in ("T1", "T2"):
            await store.start_task(task)
        first = await store.save_report("T1", REPORT)
        await store.finish_task("T1", "returned", first)
        selected = store.new_task_result_refs()
        frozen = store.manager_input_snapshot(selected)
        await store.start_manager_call("M2", selected)
        await store.start_manager_query("M2")
        await store.start_manager_query("M2")
        await store.finish_manager_query("M2")
        assert store._get("MANAGER#M2")["situation"] == "자료 확인 중"
        await store.finish_manager_query("M2")
        late = await store.save_report("T2", REPORT | {"summary": "늦은 보고"})
        await store.finish_task("T2", "returned", late)
        invalid = decision()
        store.accept_manager_run("M2", history=[{"late": False}], delivered_refs=selected, decision=invalid)
        with pytest.raises(AssignmentError):
            await store.save_assignment("M2", invalid)
        await store.reject_assignment("M2", "duplicate work IDs")
        assert store.new_task_result_refs() == [late]
        assert [r["result_ref"] for r in frozen["new_results"]] == [first]
        assert store._get("MANAGER#M2")["review_work_ids"] == ["W1"]
        await store.start_manager_call("M3", [late])
        await store.fail_manager_call("M3", "SDK unavailable")
        assert store.new_task_result_refs() == [late]
        assert store.manager_history == [{"late": False}]
    asyncio.run(case())


def test_shutdown_preserves_running_return_and_blocks_new_action():
    async def case():
        store = L4Store("shutdown")
        await assign(store)
        await store.start_task("T1")
        a = await store.create_action("W1", "T1", "record_reader", "{}")
        await store.start_action(a, {})
        store.end_execution()
        with pytest.raises(ExecutionEnded):
            await store.create_action("W1", "T1", "record_reader", "{}")
        with pytest.raises(StoreError):
            await store.save_final(REPORT)
        await store.finish_action(a, {"status": "timeout", "error": "actual timeout"})
        await finish(store)
        assert store._action(a)["native_status"] == "timeout"
        assert store.ready_tasks() == []
        with pytest.raises(StoreError):
            await store.register_file(CompletedFile("x", __import__("pathlib").Path(__file__).resolve(), "text/plain", 0, "0"*64))
    asyncio.run(case())


def test_read_result_uses_scope_numeric_cursors_and_original_body():
    async def case():
        store = L4Store("reader")
        await assign(store, decision(12))
        source = make_read_result_source(store)
        tool = ReadResultTool(source, max_list_items=20, max_data_bytes=10000)
        first = await tool.execute(dict(kind="work", id="W1", limit=9))
        second = await tool.execute(dict(kind="work", id="W1", limit=9, cursor=first["next_cursor"]))
        assert [t["id"] for t in second["data"]["tasks"]] == ["T10", "T11", "T12"]
        foreign = ReadResultTool(make_read_result_source(L4Store("other")), max_list_items=20, max_data_bytes=10000)
        assert (await foreign.execute(dict(kind="work", id="W1", limit=1, cursor=first["next_cursor"])))["error"]["code"] == "NOT_FOUND"
        invalid = await tool.execute(dict(kind="task", id="T1", limit=1, cursor=first["next_cursor"]))
        assert invalid["error"]["code"] == "INVALID_CURSOR"
        pending = await tool.execute(dict(kind="result", id="report:T1", pointer=""))
        assert pending["error"]["code"] == "RESULT_NOT_READY"
        denied = ReadResultTool(make_read_result_source(store, allowed_work_ids=set()), max_list_items=20, max_data_bytes=10000)
        assert (await denied.execute(dict(kind="task", id="T1", limit=1)))["error"]["code"] == "FORBIDDEN"
        assert not store._action_keys
    asyncio.run(case())


def test_realistic_pipeline_splits_recovers_lost_reply_and_reads_back(tmp_path):
    async def case():
        store = L4Store("회귀/job")
        io = MemoryStorageIO(page_size=1)
        io.lose_initial_reply = True
        io.lose_reply_at = {3, 8}
        io.reject_once_at = {4}
        io.expire_tokens_on_loss = True
        config = replace(CONFIG, max_transaction_items=3, inline_json_max_bytes=150)
        publisher = AwsPublisher(store, io, config)
        await publisher.initialize()
        await assign(store, decision(5))
        await store.start_task("T1")
        action = await store.create_action("W1", "T1", "record_reader", "{}")
        await store.start_action(action, {"context": {"state_id": None}})
        native = {"status": "ok", "data": "가" * 2000}
        ref = await store.finish_action(action, native)
        report = REPORT | {"findings": [{"statement": "자료 확보", "refs": [ref]}]}
        report_ref = await store.save_report("T1", report)
        await store.finish_task("T1", "returned", report_ref)
        raw = b'late completed file'
        path = tmp_path / "record.json"
        path.write_bytes(raw)
        descriptor = CompletedFile("network://records/existing", path.resolve(), "application/json", len(raw), hashlib.sha256(raw).hexdigest())
        store.end_execution()
        await store.register_file(descriptor)
        await store.register_file(descriptor)
        await finish(store)
        assert not io.requests
        task = asyncio.create_task(publisher.run())
        await store.wait_until_published()
        await task
        reader = AwsRecordReader(io)
        meta = await reader.item(store.job_id, "META")
        assert meta["status"] == "completed" and meta["last_saved_seq"] == store.last_saved_seq
        assert meta["final_result_ref"] == "final"
        assert await reader.body(await reader.item(store.job_id, "RESULT#" + ref)) == native
        assert await reader.file_bytes(await reader.item(store.job_id, "FILE#" + descriptor.file_ref)) == raw
        assert len(await reader.list_items(store.job_id, "TASK#W1#")) == 5
        assert all(len(r["TransactItems"]) <= 3 for r in io.requests)
        repeated = [r for r in io.requests if r["ClientRequestToken"] == io.requests[3]["ClientRequestToken"]]
        assert len(repeated) == 2 and repeated[0] == repeated[1]
        assert all(snapshot[(store.job_id, "META")]["status"] != "completed" for snapshot in io.history[:-1])
        assert store.pending_count == 0 and store.inflight is None
        assert (await reader.item(store.job_id, "RESULT#" + ref))["body_location"] == "s3"
        assert "%2F" in next(iter(io.objects))
    asyncio.run(case())


def test_publisher_permanent_error_retains_pending_inflight_and_fixed_request():
    async def case():
        store = L4Store("retain")
        io = MemoryStorageIO()
        io.permanent_error_at = {1}
        publisher = AwsPublisher(store, io, CONFIG)
        await assign(store)
        await finish(store)
        with pytest.raises(PublisherError):
            await publisher.run()
        with pytest.raises(PublisherError):
            await store.wait_until_published()
        assert store.inflight is not None and store.pending_count > 0
        assert publisher.inflight_requests[0].seq == 1
        assert (await io.get_meta(store.job_id))["status"] == "running"
    asyncio.run(case())


def test_duplicate_job_ownership_and_changed_file_are_not_completed(tmp_path):
    async def case():
        io = MemoryStorageIO()
        first = AwsPublisher(L4Store("same"), io, CONFIG)
        await first.initialize()
        second = AwsPublisher(L4Store("same"), io, CONFIG)
        with pytest.raises(DuplicateJobError):
            await second.initialize()
        store = L4Store("changed")
        path = tmp_path / "artifact"
        path.write_bytes(b"old")
        await store.register_file(CompletedFile("artifact://existing", path.resolve(), "image/png", 3, hashlib.sha256(b"old").hexdigest()))
        path.write_bytes(b"new")
        await finish(store)
        with pytest.raises(PublisherError):
            await AwsPublisher(store, io, CONFIG).run()
        assert await io.get_item(store.job_id, "FILE#artifact://existing") is None
        assert store.inflight is not None
    asyncio.run(case())


@pytest.mark.parametrize("body", [None, False, 0, "", [1, None, {"한글": "값"}], {"large": "x" * 409600}])
def test_codec_preserves_all_json_roots_and_falls_back_whole_body(body):
    codec = AwsCodec(CONFIG, "codec", "owner")
    record = Record.make("RESULT#result:ACT1", body, "now")
    encoded = codec.encode(Publication(1, (record,)))
    from l4_orchestrator.json_values import loads
    item = loads(encoded.items_json)[0]
    raw = encoded.uploads[0].body if item["body_location"] == "s3" else item["body_json"].encode()
    assert loads(raw) == body
    assert item_size_bound(item) < 400 * 1024


def test_non_json_input_never_partially_mutates():
    async def case():
        store = L4Store("bad-json")
        await assign(store)
        await store.start_task("T1")
        action = await store.create_action("W1", "T1", "record_reader", "{}")
        await store.start_action(action, {})
        before = (store.snapshot_records(), store.pending_count)
        with pytest.raises(ValueError):
            await store.finish_action(action, {"status": "ok", "invalid": float("nan")})
        assert before == (store.snapshot_records(), store.pending_count)
    asyncio.run(case())


def test_notion_prepare_failure_keeps_action_and_original_arguments():
    async def case():
        store = L4Store("prepare-failure")
        data = decision(1)
        data["tasks"][0]["execution"] = {
            "kind": "tool", "name": "record_reader", "arguments_json": "{invalid"}
        await assign(store, data)
        await store.start_task("T1")
        action = await store.create_action("W1", "T1", "record_reader", "{invalid")
        try:
            loads("{invalid")
        except ValueError as error:
            ref = await store.fail_action(action, "prepare", str(error))
        await store.finish_task("T1", "failed", ref)
        assert store._action(action)["arguments_json"] == "{invalid"
        assert store._action(action)["started_at"] is None
        assert (await store.read_result(ref))["stage"] == "prepare"
    asyncio.run(case())


def test_result_retry_preserves_json_types_and_manager_snapshot_shape():
    async def case():
        store = L4Store("exact-result")
        await assign(store, decision(1))
        await store.start_task("T1")
        action = await store.create_action("W1", "T1", "record_reader", "{}")
        await store.start_action(action, {})
        ref = await store.finish_action(action, {"status": "ok", "data": True})
        assert await store.finish_action(action, {"data": True, "status": "ok"}) == ref
        with pytest.raises(StoreError):
            await store.finish_action(action, {"status": "ok", "data": 1})
        assert not same_json(1, 1.0)
        report_ref = await store.save_report("T1", REPORT)
        await store.finish_task("T1", "returned", report_ref)
        snapshot = store.manager_input_snapshot([report_ref])
        assert snapshot["next_ids"] == {"work": "W2", "task": "T2"}
        assert snapshot["works"] == [{"id": "W1", "tasks": [
            {"id": "T1", "status": "returned", "result_ref": report_ref}]}]
        assert snapshot["new_results"] == [{"work_id": "W1", "task_id": "T1", "status": "returned",
            "data": REPORT, "error": None, "result_ref": report_ref}]
    asyncio.run(case())
