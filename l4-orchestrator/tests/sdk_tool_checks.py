"""Run native Tool checks through the public SDK entry and actual model-input boundary."""
from copy import deepcopy
from dataclasses import dataclass, replace
import inspect
import json

from l4_orchestrator import run_l4
from l4_orchestrator.json_values import dumps
from l4_orchestrator.sdk_registry import register_native_tools, store_reader_binding
from l4_orchestrator.tools.record_reader import RecordReader
from test_sdk_runtime import LIMITS, RUN_CONFIG, ScriptModel, body, report, review, setup, task, turn, work


@dataclass
class NativeRun:
    store: object
    results: list
    actions: list
    prepared_inputs: list
    manager_inputs: list
    model_inputs: list


async def run_native_steps(tools, steps, *, files=None, initial_findings=None):
    """Each step is (native name, fixture input or callback receiving prior results).

    Browser fixtures already carry native tracking IDs. Strip only those IDs for
    the scripted model, then verify the runtime supplied the W/T/ACT context while
    preserving the original performing arguments and the following model input.
    This helper uses no legacy decisions, graph or ledger compatibility layer.
    """
    store, _, io, publisher = setup()
    tools = dict(tools)
    tools.setdefault("record_reader", RecordReader({}, max_data_bytes=20000))
    registry = register_native_tools(tools)
    if "read_result" not in registry:
        registry = registry.replacing(store_reader_binding(store, max_list_items=20, max_data_bytes=20000))
    results, submitted, expected_inputs, messages = [], [], [], []

    async def decide(call):
        data = body(call)
        messages.append(deepcopy(data))
        if submitted:
            number = len(submitted)
            saved = await store.read_result(f"result:ACT{number}")
            assert len(data["new_results"]) == 1
            received = data["new_results"][0]
            assert received["result_ref"] == f"result:ACT{number}"
            assert received["data"] == saved
            results.append(saved)
        if len(submitted) == len(steps):
            return turn(finish=report(f"result:ACT{len(steps)}"))
        number = len(submitted) + 1
        name, source = steps[number - 1]
        source = source(deepcopy(results)) if callable(source) else deepcopy(source)
        if inspect.isawaitable(source):
            source = await source
        original = deepcopy(source)
        arguments = deepcopy(source)
        if registry[name].action_context:
            arguments.pop("action_id", None)
            arguments.pop("tool", None)
            for key in ("job_id", "scenario_id", "step_id"):
                arguments["context"].pop(key, None)
        expected = deepcopy(arguments)
        if registry[name].action_context:
            expected.update(action_id=f"ACT{number}", tool=name)
            expected["context"].update(job_id=store.job_id, scenario_id=f"T{number}", step_id=f"ACT{number}")
        assert source == original
        submitted.append(arguments)
        expected_inputs.append(expected)
        return turn(works=[work(list(dict.fromkeys(name for name, _ in steps)))] if number == 1 else [],
            tasks=[task(f"T{number}", execution={"kind": "tool", "name": name,
                                               "arguments_json": dumps(arguments)})],
            review=review(f"T{number}"))

    manager = ScriptModel(*([decide] * (len(steps) + 1)))
    # Input meanings and resource settings stay owned by each native test fixture.
    await run_l4(job_id=store.job_id, initial_findings={} if initial_findings is None else initial_findings, previous_judgment={},
        store=store, publisher=publisher, registry=registry, model_name=manager,
        executor_model=ScriptModel(), execution_limits=replace(LIMITS, manager_calls=len(steps) + 2),
        files=files, run_config=RUN_CONFIG)
    actions = [r.body() for r in store.snapshot_records() if r.record_key.startswith("ACTION#")]
    assert len(actions) == len(steps) and len(results) == len(steps)
    prepared = []
    for number, action in enumerate(actions, 1):
        assert action["action_id"] == f"ACT{number}"
        assert json.loads(action["arguments_json"]) == submitted[number - 1]
        actual = json.loads(action["prepared_input_json"])
        # Native defaults may be added by prepare; every supplied argument is unchanged.
        for key, value in expected_inputs[number - 1].items():
            if isinstance(value, dict):
                assert all(actual[key][k] == v for k, v in value.items())
            else:
                assert actual[key] == value
        prepared.append(actual)
    assert io.items[(store.job_id, "META")]["status"] == "completed"
    return NativeRun(store, results, actions, prepared, messages,
                     [deepcopy(call["input"]) for call in manager.calls])
