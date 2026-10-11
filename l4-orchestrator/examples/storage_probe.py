"""Exercise the storage contract without Agents SDK or a browser.

python -m examples.storage_probe --output <directory> [--aws --job-id <fresh-id>]
All producer data is explicitly synthetic. --aws writes only the configured L4
table and l4/ objects; it does not provision resources or change IAM.
"""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
from uuid import uuid4

from l4_orchestrator.storage import L4Store, CompletedFile
from l4_orchestrator.json_values import same_json
from l4_orchestrator.storage.aws_codec import AwsStorageConfig
from l4_orchestrator.storage.aws_io import Boto3StorageIO
from l4_orchestrator.storage.aws_publisher import AwsPublisher
from l4_orchestrator.storage.aws_reader import AwsRecordReader
from l4_orchestrator.storage.read_result_source import make_read_result_source
from l4_orchestrator.tools.read_result import ReadResultTool
from examples.storage_memory_io import MemoryStorageIO


async def produce(store, output):
    """Call the same Store methods that the future runtime/Tool bridge will use."""
    work = {"id": "W1", "title": "검증 입력의 반환 확인", "question": "원문과 근거가 보존되는가",
            "reason": "저장 경로 독립 검증", "scope": {"target_refs": ["fixture:source"],
            "allowed_tools": ["fixture_reader"], "restrictions": ["실제 사이트 조사 아님"]}}
    direct = {"kind": "tool", "name": "fixture_reader", "arguments_json": '{"source":"fixture:source"}'}
    agent = {"kind": "agent", "instruction": "합성 입력의 보존 확인", "allowed_tools": ["fixture_reader"], "input_refs": ["fixture:source"]}
    decision = {"summary": "저장 검증용 배정", "new_works": [work], "tasks": [
        {"id": "T1", "work_id": "W1", "title": "직접 Tool 결과", "after": [], "execution": direct},
        {"id": "T2", "work_id": "W1", "title": "Agent 내부 결과와 최종 보고", "after": ["T1"], "execution": agent},
        {"id": "T3", "work_id": "W1", "title": "기술 실패 결과", "after": ["T1"], "execution": direct},
        {"id": "T4", "work_id": "W1", "title": "총괄 종료 때 미시작", "after": ["T2"], "execution": agent}],
        "review_after": {"tasks": ["T1"], "when": "all"}, "work_answers": [], "finish": None}
    await store.start_manager_call("fixture-M1", [])
    store.accept_manager_run("fixture-M1", history=[{"role": "user", "content": "synthetic input"}],
                             delivered_refs=[], decision=decision)
    await store.save_assignment("fixture-M1", decision)
    await store.start_task("T1")
    a = await store.create_action("W1", "T1", "fixture_reader", direct["arguments_json"])
    await store.start_action(a, {"source": "fixture:source", "job_id": store.job_id})
    original = {"status": "ok", "data": {"marker": [False, None, 0, "원문"], "large": "가" * 100000}}
    first_ref = await store.finish_action(a, original)
    await store.finish_task("T1", "success", first_ref)
    selected = store.new_task_result_refs()
    manager_input = store.manager_input_snapshot(selected)
    await store.start_manager_call("fixture-M2", selected)
    await store.start_manager_query("fixture-M2")
    tool = ReadResultTool(make_read_result_source(store), max_list_items=20, max_data_bytes=8192)
    model_reply = await tool.execute({"kind": "result", "id": first_ref, "pointer": "/data/marker"})
    await store.finish_manager_query("fixture-M2")
    await store.start_task("T2")
    a = await store.create_action("W1", "T2", "fixture_reader", "{}")
    await store.start_action(a, {})
    internal_ref = await store.finish_action(a, {"status": "ok", "data": {"source": "fixture"}})
    report = {"summary": "합성 입력을 확인함", "findings": [{"statement": "입력 보존", "refs": [internal_ref]}], "limits": ["실제 Agent 실행 아님"]}
    late_ref = await store.save_report("T2", report)
    await store.finish_task("T2", "returned", late_ref)
    await store.start_task("T3")
    a = await store.create_action("W1", "T3", "fixture_reader", direct["arguments_json"])
    await store.start_action(a, {})
    failed_ref = await store.finish_action(a, {"status": "timeout", "error": {"code": "FIXTURE_TIMEOUT", "message": "합성 실패 입력"}})
    await store.finish_task("T3", "failed", failed_ref)
    final = {"summary": "저장 경로 검증용 최종 결과", "findings": [{"statement": "M2 시작 시 받은 원문", "refs": [first_ref]}], "limits": ["실제 URL 판단 아님", "M2 시작 뒤 T2·T3 결과는 총괄 입력에 포함되지 않음"]}
    final_decision = {"summary": "확보한 입력으로 종료", "new_works": [], "tasks": [], "review_after": None,
                      "work_answers": [{"work_id": "W1", "answer": "합성 입력 수신 확인", "refs": [first_ref]}], "finish": final}
    store.accept_manager_run("fixture-M2", history=[{"role": "assistant", "content": "synthetic finish"}],
                             delivered_refs=selected, decision=final_decision)
    await store.save_assignment("fixture-M2", final_decision)
    store.end_execution()
    await store.finish_task("T4", "ended_by_manager")
    raw = b'{"fixture":"completed after Tool return"}'
    path = output / "completed-file.json"
    path.write_bytes(raw)
    descriptor = CompletedFile("network://records/fixture-existing-ref", path.resolve(), "application/json",
                               len(raw), hashlib.sha256(raw).hexdigest(), '{"capture_id":"fixture-capture"}')
    await store.register_file(descriptor)
    await store.save_final(final)
    store.seal_records()
    return {"manager_selected_refs": selected, "undelivered_final_refs": store.new_task_result_refs(),
            "model_query_reply": model_reply, "selected_marker": manager_input["new_results"][0]["data"]["data"]["marker"]}


async def run(args):
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    config = AwsStorageConfig(args.region, args.table, args.bucket)
    store = L4Store(args.job_id or "l4-storage-probe-" + uuid4().hex)
    if args.aws:
        import boto3
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        account = session.client("sts").get_caller_identity()["Account"]
        if account != "998301375101" or args.bucket != "team5-evidence-998301375101-ap-northeast-2-an":
            raise RuntimeError("Probe must use the authorized project AWS account and evidence bucket")
        io = Boto3StorageIO.from_session(session, config)
    else:
        io = MemoryStorageIO()
    publisher = AwsPublisher(store, io, config)
    await publisher.initialize()
    publishing = asyncio.create_task(publisher.run())
    try:
        evidence = await produce(store, output)
        await store.wait_until_published()
        await publishing
    finally:
        if not publishing.done():
            publishing.cancel()
        await asyncio.gather(publishing, return_exceptions=True)
    reader = AwsRecordReader(io)
    items = await reader.list_items(store.job_id, "")
    expected = {r.record_key: r.body() for r in store.snapshot_records()}
    checked = []
    for item in items:
        key = item["record_key"]
        if key.startswith("FILE#"):
            await reader.file_bytes(item)
        elif key != "META":
            body = await reader.body(item)
            assert same_json(body, expected[key]), key
        checked.append(key)
    assert set(checked) == set(expected)
    meta = await reader.item(store.job_id, "META")
    assert meta["status"] == "completed" and meta["last_saved_seq"] == store.last_saved_seq
    summary = {"job_id": store.job_id, "transport": "aws" if args.aws else "memory_standin",
               "producer": "synthetic fixture; no Agent or browser execution", "verified_record_keys": checked,
               "last_saved_seq": store.last_saved_seq, "status": meta["status"], **evidence}
    for name, data in [("verification.json", summary), ("aws-items.json", items)]:
        (output/name).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"job_id": store.job_id, "transport": summary["transport"], "verified_records": len(checked),
                      "status": meta["status"], "output": str(output)}, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--aws", action="store_true")
    parser.add_argument("--job-id")
    parser.add_argument("--profile")
    parser.add_argument("--region", default="ap-northeast-2")
    parser.add_argument("--table", default="Team5-l4DB")
    parser.add_argument("--bucket", default="team5-evidence-998301375101-ap-northeast-2-an")
    asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    main()
