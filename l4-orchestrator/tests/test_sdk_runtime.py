"""Actual SDK Runner/FunctionTool loops with a deterministic model boundary."""
import asyncio
from copy import deepcopy
import inspect
import json

from agents import Model, RunConfig
from agents.items import ModelResponse
from agents.usage import Usage
from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText
from pydantic import BaseModel, ConfigDict
import pytest

from examples.storage_memory_io import MemoryStorageIO
from l4_orchestrator.execution_control import ExecutionEnded, StoreError
from l4_orchestrator.json_values import dumps
from l4_orchestrator.ports import ExecutionPort
from l4_orchestrator.sdk_files import FileConnections
from l4_orchestrator.sdk_registry import ToolBinding, ToolRegistry, register_native_tools, store_reader_binding
from l4_orchestrator.sdk_runtime import L4Runtime, run_l4
from l4_orchestrator.sdk_tools import make_executor_tools, run_tool
from l4_orchestrator.sdk_types import ExecutionLimits, ManagerTurn
from l4_orchestrator.storage.aws_codec import AwsStorageConfig
from l4_orchestrator.storage.aws_publisher import AwsPublisher
from l4_orchestrator.storage.store import L4Store
from l4_orchestrator.tools.record_reader import RecordReader


class ScriptModel(Model):
    def __init__(self, *steps):
        self.steps = list(steps)
        self.calls = []

    async def get_response(self, system_instructions, input, model_settings, tools,
                           output_schema, handoffs, tracing, **kwargs):
        call = dict(instructions=system_instructions, input=deepcopy(input),
                    tools=tools, settings=model_settings, output_schema=output_schema)
        self.calls.append(call)
        assert self.steps, "Unexpected extra model call"
        step = self.steps.pop(0)
        if callable(step):
            step = step(call)
            if inspect.isawaitable(step):
                step = await step
        if isinstance(step, BaseException):
            raise step
        if isinstance(step, ResponseFunctionToolCall):
            output = [step]
        else:
            output = [ResponseOutputMessage(id=f"msg_{len(self.calls)}", type="message", role="assistant",
                      status="completed", content=[ResponseOutputText(type="output_text",
                      text=dumps(step), annotations=[])])]
        return ModelResponse(output=output, usage=Usage(), response_id=f"response_{len(self.calls)}")

    async def stream_response(self, *args, **kwargs):
        raise NotImplementedError
        yield


def tool_call(name, arguments, identity):
    return ResponseFunctionToolCall(id=identity, call_id=identity, type="function_call",
                                    name=name, arguments=dumps(arguments), status="completed")


def report(ref="result:ACT1"):
    return {"summary": "관찰 보고", "findings": [{"statement": "입력 그대로 관찰", "refs": [ref]}],
            "limits": ["통제된 입력의 실행 검증"]}


def work(tools=("echo",)):
    return {"id": "W1", "title": "관찰", "question": "실제 반환은 무엇인가?", "reason": "기존 자료 확인",
            "scope": {"target_refs": [], "allowed_tools": list(tools), "restrictions": []}}


def task(identity="T1", *, execution=None, after=()):
    return {"id": identity, "work_id": "W1", "title": identity, "after": list(after),
            "execution": execution or {"kind": "tool", "name": "echo", "arguments_json": '{"text":"원문"}'}}


def turn(*, works=(), tasks=(), review=None, finish=None, answers=()):
    return dict(summary="검토", new_works=list(works), tasks=list(tasks), review_after=review,
                work_answers=list(answers), finish=finish)


def review(*tasks):
    return {"tasks": list(tasks), "when": "all"}


class EchoInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    text: str


def echo_binding(invoke=None, *, uses_page=False):
    async def echo(value):
        return {"status": "ok", "data": {"text": value["text"], "native": [1, False, None]}}

    port = ExecutionPort(description="Echo a controlled observation", kind="tool", provenance="existing_material",
        permission_description="Controlled local input", prepare=lambda request, _: EchoInput.model_validate(
            request["arguments"]).model_dump(mode="json"), invoke=invoke or echo)
    return ToolBinding("echo", port, EchoInput, uses_page=uses_page)


def setup(*bindings):
    store = L4Store("sdk-local")
    registry = register_native_tools({"record_reader": RecordReader({}, max_data_bytes=10000)})
    registry = registry.replacing(store_reader_binding(store, max_list_items=10, max_data_bytes=10000))
    for binding in bindings or (echo_binding(),):
        registry = registry.replacing(binding)
    io = MemoryStorageIO()
    publisher = AwsPublisher(store, io, AwsStorageConfig("test-region", "test-table", "test-bucket"))
    return store, registry, io, publisher


LIMITS = ExecutionLimits(None, 10, 10, None, None)
RUN_CONFIG = RunConfig(tracing_disabled=True)


async def execute(manager, executor, *, setup_values=None, files=None, limits=LIMITS):
    store, registry, io, publisher = setup_values or setup()
    result = await run_l4(job_id=store.job_id, initial_findings={"caller_owned": "보존"},
        previous_judgment={"label": "SUSPICIOUS", "limits": ["추가 확인"]},
        store=store, publisher=publisher, registry=registry, model_name=manager,
        executor_model=executor, execution_limits=limits, files=files, run_config=RUN_CONFIG)
    return result, store, io


def body(call):
    return json.loads(next(i["content"] for i in reversed(call["input"]) if i.get("role") == "user"))


def test_sdk_query_direct_task_executor_report_and_confirmed_publication():
    async def check():
        store, registry, io, publisher = setup()
        def after_query(call):
            assert not [r for r in store.snapshot_records() if r.record_key.startswith("ACTION#")]
            return turn(works=[work()], tasks=[task()], review=review("T1"))
        def second(call):
            data = body(call)
            assert data["new_results"][0]["data"] == await_result[0]
            assert data["new_results"][0]["result_ref"] == "result:ACT1"
            return turn(tasks=[task("T2", execution={"kind": "agent", "instruction": "결과를 보며 두 번 확인",
                        "allowed_tools": ["echo"], "input_refs": ["result:ACT1"]})], review=review("T2"))
        await_result = [{"status": "ok", "data": {"text": "원문", "native": [1, False, None]}}]
        def last(call):
            data = body(call)
            assert len(data["new_results"]) == 1 and data["new_results"][0]["result_ref"] == "report:T2"
            assert data["works"][0]["tasks"][-1]["status"] == "returned"
            return turn(finish=report("report:T2"), answers=[{"work_id": "W1", "answer": "자료 확인",
                                                           "refs": ["report:T2"]}])
        manager = ScriptModel(tool_call("record_reader", {"record_ref": "missing", "pointer": ""}, "q1"),
                              after_query, second, last)
        executor = ScriptModel(tool_call("echo", {"text": "첫 행동"}, "e1"),
                               tool_call("echo", {"text": "둘째 행동"}, "e2"), report("result:ACT3"))
        result, _, _ = await execute(manager, executor, setup_values=(store, registry, io, publisher))
        assert result.summary == "관찰 보고" and len(manager.calls) == 4 and len(executor.calls) == 3
        assert all(c["settings"].parallel_tool_calls is False for c in executor.calls)
        assert "업무의 질문" in executor.calls[0]["instructions"]
        assert "실제 반환은 무엇인가?" in dumps(executor.calls[0]["input"])
        assert await store.read_result("result:ACT1") == await_result[0]
        assert await store.read_result("result:ACT3") == {"status": "ok", "data": {"text": "둘째 행동", "native": [1, False, None]}}
        assert [r.body()["action_id"] for r in store.snapshot_records() if r.record_key.startswith("ACTION#")] == ["ACT1", "ACT2", "ACT3"]
        assert io.items[(store.job_id, "META")]["status"] == "completed"
        assert store.pending_count == 0 and store.inflight is None
        # Previous input list is replaced, never appended to itself.
        inputs = [i for i in store.manager_history if i.get("role") == "user"]
        assert len(inputs) == 3
        assert [len(json.loads(i["content"])["new_results"]) for i in inputs] == [0, 1, 1]
    asyncio.run(check())


@pytest.mark.parametrize("finish_early", [True, False])
def test_late_parallel_result_only_triggers_review_when_manager_requests_it(finish_early):
    async def check():
        slow_started, release = asyncio.Event(), asyncio.Event()
        async def echo(value):
            if value["text"] == "slow":
                slow_started.set()
                await release.wait()
            return {"status": "ok", "data": value}
        setup_values = setup(echo_binding(echo))
        store = setup_values[0]
        async def second(call):
            await slow_started.wait()
            assert [r["task_id"] for r in body(call)["new_results"]] == ["T1"]
            if finish_early:
                async def later():
                    while not store.execution_ended:
                        await asyncio.sleep(0)
                    release.set()
                asyncio.create_task(later())
                return turn(finish=report())
            release.set()
            while not store.task_has_ended("T2"):
                await asyncio.sleep(0)
            return turn(review=review("T2"))
        def third(call):
            assert [r["task_id"] for r in body(call)["new_results"]] == ["T2"]
            return turn(finish=report("result:ACT2"))
        steps = [turn(works=[work()], tasks=[task(), task("T2", execution={"kind": "tool", "name": "echo",
                    "arguments_json": '{"text":"slow"}'})], review=review("T1")), second]
        manager = ScriptModel(*(steps if finish_early else steps + [third]))
        await execute(manager, ScriptModel(), setup_values=setup_values)
        assert store.task_has_ended("T2")
        assert await store.read_result("result:ACT2") == {"status": "ok", "data": {"text": "slow"}}
        assert len(manager.calls) == (2 if finish_early else 3)
        assert store.new_task_result_refs() == (["result:ACT2"] if finish_early else [])
    asyncio.run(check())


def test_whole_invalid_assignment_is_rejected_before_any_task_runs():
    async def check():
        def correction(call):
            assert "registration_error" in body(call)
            assert body(call)["next_ids"] == {"work": "W1", "task": "T1"}
            return turn(works=[work()], tasks=[task()], review=review("T1"))
        manager = ScriptModel(turn(works=[work()], tasks=[task(), task("T3")], review=review("T1")),
                              correction, turn(finish=report()))
        _, store, _ = await execute(manager, ScriptModel())
        assert len([r for r in store.snapshot_records() if r.record_key.startswith("ACTION#")]) == 1
        statuses = [r.body()["registration_status"] for r in store.snapshot_records() if r.record_key.startswith("MANAGER#")]
        assert statuses == ["rejected", "registered", "registered"]
    asyncio.run(check())


@pytest.mark.parametrize("page_id", [None, "page-selected"])
def test_native_argument_positions_are_preserved_and_tracking_fields_injected(page_id):
    from l4_orchestrator.tools.get_page_state import GetPageStateInput
    prepared = []
    binding = ToolBinding("get_page_state", ExecutionPort("state", "tool", "new_observation", "local",
        lambda request, _: prepared.append(request["arguments"]) or GetPageStateInput.model_validate(
            request["arguments"]).model_dump(mode="json"), None), GetPageStateInput, True, True)
    arguments = {"target": None, "params": {}, "context": {"state_id": "observed-state"}}
    if page_id is not None:
        arguments["context"]["page_id"] = page_id
    expected_context = deepcopy(arguments["context"])
    native = binding.prepare(arguments, job_id="J", task={"id": "T2"}, action_id="ACT3")
    assert native == {"action_id": "ACT3", "tool": "get_page_state", "target": None, "params": {},
                      "context": {**expected_context, "job_id": "J", "scenario_id": "T2", "step_id": "ACT3"}}
    assert arguments["context"] == expected_context
    schema = binding.model_input_schema()
    assert set(schema["properties"]) == {"target", "params", "context"}
    assert set(schema["$defs"]["ActionContext"]["properties"]) == {"state_id", "page_id"}


def test_manager_runner_failure_keeps_selected_results_undelivered():
    async def check():
        store, registry, _, _ = setup()
        model = ScriptModel(RuntimeError("controlled model transport failure"))
        runtime = L4Runtime(store=store, registry=registry, model_name=model, executor_model=ScriptModel(),
                            execution_limits=LIMITS, run_config=RUN_CONFIG)
        decision = ManagerTurn.model_validate(turn(works=[work()], tasks=[task()], review=review("T1")))
        await store.start_manager_call("setup", [])
        store.accept_manager_run("setup", history=[], delivered_refs=[], decision=decision)
        await store.save_assignment("setup", decision)
        await runtime.execute_saved_task(await store.read_task("T1"))
        refs = store.new_task_result_refs()
        with pytest.raises(RuntimeError, match="controlled model"):
            await runtime.run_manager(runtime.manager_input(refs), refs)
        assert store.manager_history == [] and store.new_task_result_refs() == refs
        assert [r.body()["status"] for r in store.snapshot_records() if r.record_key.startswith("MANAGER#")] == ["returned", "failed"]
    asyncio.run(check())


def test_page_lock_covers_entire_executor_task_and_sdk_stop_preserves_actual_return():
    async def check():
        observed = []
        first_running, finish_first = asyncio.Event(), asyncio.Event()
        async def echo(value):
            observed.append(value["text"])
            if value["text"] == "first":
                first_running.set()
                await finish_first.wait()
            return {"status": "ok", "data": value}
        store, registry, _, _ = setup(echo_binding(echo, uses_page=True))
        executor = ScriptModel(tool_call("echo", {"text": "first"}, "first-call"))
        runtime = L4Runtime(store=store, registry=registry, model_name=ScriptModel(), executor_model=executor,
                            execution_limits=LIMITS, run_config=RUN_CONFIG)
        decision = ManagerTurn.model_validate(turn(works=[work()], tasks=[
            task(execution={"kind": "agent", "instruction": "첫 작업", "allowed_tools": ["echo"], "input_refs": []}),
            task("T2")], review=review("T1", "T2")))
        await store.start_manager_call("setup", [])
        store.accept_manager_run("setup", history=[], delivered_refs=[], decision=decision)
        await runtime.register_turn("setup", decision)
        runtime.running["T1"] = asyncio.create_task(runtime.execute_saved_task(await store.read_task("T1")))
        await first_running.wait()
        runtime.running["T2"] = asyncio.create_task(runtime.execute_saved_task(await store.read_task("T2")))
        await asyncio.sleep(0)
        assert (await store.read_task("T2"))["status"] == "waiting"
        store.end_execution()
        finish_first.set()
        await runtime.stop_tasks()
        assert observed == ["first"] and len(executor.calls) == 1
        assert await store.read_result("result:ACT1") == {"status": "ok", "data": {"text": "first"}}
        assert (await store.read_task("T1"))["status"] == "ended_by_manager"
        assert (await store.read_task("T2"))["status"] == "ended_by_manager"
        assert "RESULT#report:T1" not in {r.record_key for r in store.snapshot_records()}
    asyncio.run(check())


def test_prepare_failure_keeps_original_arguments_and_does_not_invoke_native_tool():
    async def check():
        store, registry, _, _ = setup()
        runtime = L4Runtime(store=store, registry=registry, model_name=ScriptModel(), executor_model=ScriptModel(),
                            execution_limits=LIMITS, run_config=RUN_CONFIG)
        broken = task(execution={"kind": "tool", "name": "echo", "arguments_json": '{malformed'})
        decision = ManagerTurn.model_validate(turn(works=[work()], tasks=[broken], review=review("T1")))
        await store.start_manager_call("setup", [])
        store.accept_manager_run("setup", history=[], delivered_refs=[], decision=decision)
        await runtime.register_turn("setup", decision)
        await runtime.execute_saved_task(await store.read_task("T1"))
        saved = next(r.body() for r in store.snapshot_records() if r.record_key.startswith("ACTION#"))
        assert saved["arguments_json"] == '{malformed' and saved["prepared_input_json"] is None
        assert saved["error"]["stage"] == "prepare" and saved["status"] == "failed"
        assert (await store.read_task("T1"))["result_ref"] == "result:ACT1"
    asyncio.run(check())


def test_task_limit_waits_for_native_return_before_releasing_task():
    from dataclasses import replace
    async def check():
        async def echo(value):
            await asyncio.sleep(.04)
            return {"status": "ok", "data": value}
        store, registry, _, _ = setup(echo_binding(echo))
        runtime = L4Runtime(store=store, registry=registry, model_name=ScriptModel(), executor_model=ScriptModel(),
                            execution_limits=replace(LIMITS, task_seconds=.01), run_config=RUN_CONFIG)
        decision = ManagerTurn.model_validate(turn(works=[work()], tasks=[task()], review=review("T1")))
        await store.start_manager_call("setup", [])
        store.accept_manager_run("setup", history=[], delivered_refs=[], decision=decision)
        await runtime.register_turn("setup", decision)
        await runtime.execute_saved_task(await store.read_task("T1"))
        assert (await store.read_result("result:ACT1"))["status"] == "ok"
        assert (await store.read_result("report:T1"))["stage"] == "task_limit"
        assert (await store.read_task("T1"))["status"] == "failed"
    asyncio.run(check())


def test_store_failure_from_sdk_tool_is_not_converted_to_model_error_text():
    async def check():
        store, registry, _, _ = setup()
        class BrokenFiles(FileConnections):
            async def register_completed(self, store):
                raise StoreError("controlled recording failure")
        executor = ScriptModel(tool_call("echo", {"text": "real-return"}, "action"))
        runtime = L4Runtime(store=store, registry=registry, model_name=ScriptModel(), executor_model=executor,
                            execution_limits=LIMITS, run_config=RUN_CONFIG, files=BrokenFiles())
        decision = ManagerTurn.model_validate(turn(works=[work()], tasks=[task(execution={
            "kind": "agent", "instruction": "관찰", "allowed_tools": ["echo"], "input_refs": []})], review=review("T1")))
        await store.start_manager_call("setup", [])
        store.accept_manager_run("setup", history=[], delivered_refs=[], decision=decision)
        await runtime.register_turn("setup", decision)
        with pytest.raises(StoreError, match="controlled recording"):
            await runtime.execute_saved_task(await store.read_task("T1"))
        assert len(executor.calls) == 1
        assert "RESULT#report:T1" not in {r.record_key for r in store.snapshot_records()}
    asyncio.run(check())


def test_report_is_preserved_with_unresolvable_reference_information_for_manager():
    async def check():
        original = report("result:ACT19")
        def final_review(call):
            received = body(call)["new_results"][0]["data"]
            assert all(received[k] == v for k, v in original.items())
            assert received["reference_errors"] == [{"ref": "result:ACT19",
                "reason": "No saved result exists for this reference"}]
            return turn(finish=report("report:T1"))
        manager = ScriptModel(turn(works=[work()], tasks=[task(execution={"kind": "agent",
            "instruction": "보고", "allowed_tools": ["echo"], "input_refs": []})], review=review("T1")), final_review)
        _, store, io = await execute(manager, ScriptModel(original))
        assert (await store.read_task("T1"))["status"] == "returned"
        saved = await store.read_result("report:T1")
        assert saved["findings"] == original["findings"]
        assert "RESULT#report:T1" in {key for job, key in io.items}
    asyncio.run(check())


def test_manager_call_budget_reserves_final_judgment_on_results_already_obtained():
    from dataclasses import replace
    from l4_orchestrator.sdk_types import FinalManagerTurn
    async def check():
        def final_review(call):
            assert call["output_schema"].output_type is FinalManagerTurn
            data = body(call)
            assert data["execution_limit"]["reason"] == "manager_calls"
            assert data["new_results"][0]["data"]["data"]["text"] == "원문"
            return turn(finish=report())
        manager = ScriptModel(turn(works=[work()], tasks=[task()], review=review("T1")), final_review)
        _, store, io = await execute(manager, ScriptModel(), limits=replace(LIMITS, manager_calls=2))
        assert len(manager.calls) == 2
        assert io.items[(store.job_id, "META")]["status"] == "completed"
        assert await store.read_result("final") == report()
    asyncio.run(check())


def test_analysis_time_limit_leads_to_manager_judgment_after_recording_inflight_result():
    from dataclasses import replace
    async def check():
        async def slow(value):
            await asyncio.sleep(.8)
            return {"status": "ok", "data": value}
        def final_review(call):
            data = body(call)
            assert data["execution_limit"]["reason"] == "analysis_seconds"
            assert data["new_results"][0]["data"] == {"status": "ok", "data": {"text": "원문"}}
            return turn(finish=report())
        manager = ScriptModel(turn(works=[work()], tasks=[task()], review=review("T1")), final_review)
        _, store, io = await execute(manager, ScriptModel(), setup_values=setup(echo_binding(slow)),
                                     limits=replace(LIMITS, analysis_seconds=.5))
        assert len(manager.calls) == 2 and store.task_has_ended("T1")
        assert io.items[(store.job_id, "META")]["status"] == "completed"
    asyncio.run(check())


def test_manager_api_failure_flushes_existing_records_without_inventing_final():
    from openai import APIConnectionError
    import httpx
    async def check():
        values = setup()
        failure = APIConnectionError(request=httpx.Request("POST", "https://api.openai.com/v1/responses"))
        manager = ScriptModel(turn(works=[work()], tasks=[task()], review=review("T1")), failure)
        with pytest.raises(APIConnectionError):
            await execute(manager, ScriptModel(), setup_values=values)
        store, _, io, _ = values
        assert store.records_sealed and store.pending_count == 0 and store.inflight is None
        assert io.items[(store.job_id, "META")]["status"] == "finalizing"
        assert io.items[(store.job_id, "META")]["final_result_ref"] is None
        assert (store.job_id, "RESULT#final") not in io.items
        assert (store.job_id, "RESULT#result:ACT1") in io.items
        assert store.new_task_result_refs() == ["result:ACT1"]
    asyncio.run(check())


def test_manager_sdk_turn_limit_leaves_a_final_judgment_call():
    from dataclasses import replace
    async def check():
        def final_review(call):
            assert body(call)["execution_limit"]["reason"] == "runner_turns"
            return turn(finish={"summary": "추가 자료 확보 한계", "findings": [], "limits": ["조회 반복 한도"]})
        manager = ScriptModel(tool_call("record_reader", {"record_ref": "missing", "pointer": ""}, "query"),
                              final_review)
        _, store, io = await execute(manager, ScriptModel(), limits=replace(LIMITS, runner_turns=1))
        assert len(manager.calls) == 2
        assert io.items[(store.job_id, "META")]["status"] == "completed"
    asyncio.run(check())


def test_time_limit_preserves_agent_actions_for_manager_query_before_final():
    from dataclasses import replace
    async def check():
        async def slow(value):
            await asyncio.sleep(.8)
            return {"status": "ok", "data": value}
        def query_incomplete_task(call):
            data = body(call)
            assert data["execution_limit"]["reason"] == "analysis_seconds"
            assert data["works"][0]["tasks"][0]["status"] == "waiting"
            return tool_call("read_result", {"kind": "task", "id": "T1", "limit": 5}, "read-limited-task")
        def final_review(call):
            output = next(i["output"] for i in reversed(call["input"]) if i.get("type") == "function_call_output")
            result = json.loads(output)
            assert result["status"] == "ok"
            assert "result:ACT1" in output and "success" in output
            return turn(finish=report())
        manager = ScriptModel(turn(works=[work()], tasks=[task(execution={"kind": "agent", "instruction": "관찰",
            "allowed_tools": ["echo"], "input_refs": []})], review=review("T1")), query_incomplete_task, final_review)
        executor = ScriptModel(tool_call("echo", {"text": "한도 전 시작"}, "first-action"))
        _, store, io = await execute(manager, executor, setup_values=setup(echo_binding(slow)),
                                     limits=replace(LIMITS, analysis_seconds=.5))
        assert (await store.read_result("result:ACT1"))["data"]["text"] == "한도 전 시작"
        assert (await store.read_task("T1"))["status"] == "ended_by_manager"
        assert len(executor.calls) == 1
        assert io.items[(store.job_id, "META")]["status"] == "completed"
    asyncio.run(check())


@pytest.mark.parametrize("runner_turns", [1, 2])
def test_final_manager_reserves_its_last_response_for_judgment(runner_turns):
    from dataclasses import replace
    async def check():
        def final_review(call):
            outputs = [i for i in call["input"] if i.get("type") == "function_call_output"]
            if runner_turns == 2 and not outputs:
                assert {tool.name for tool in call["tools"]} == {"record_reader", "read_result"}
                return tool_call("read_result", {"kind": "result", "id": "result:ACT1", "pointer": ""},
                                 "final-read")
            assert call["tools"] == []
            assert "마지막 판단" in call["instructions"]
            if outputs:
                assert json.loads(outputs[-1]["output"])["status"] == "ok"
                assert "원문" in outputs[-1]["output"]
            return turn(finish=report())
        manager = ScriptModel(turn(works=[work()], tasks=[task()], review=review("T1")),
                              *([final_review] * runner_turns))
        _, store, io = await execute(manager, ScriptModel(),
            limits=replace(LIMITS, manager_calls=2, runner_turns=runner_turns))
        assert len(manager.calls) == 1 + runner_turns
        assert io.items[(store.job_id, "META")]["status"] == "completed"
        assert (await store.read_result("final"))["findings"] == report()["findings"]
    asyncio.run(check())
