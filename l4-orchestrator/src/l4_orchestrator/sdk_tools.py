"""SDK queries and assigned Tool actions have deliberately different recording paths."""
import asyncio

from agents import FunctionTool
from agents.tool import set_function_tool_failure_error_function

from .execution_control import ExecutionEnded, StoreError
from .json_values import dumps, loads
from .storage.store import normalize_status


def _sdk_tool(binding, invoke, *, is_enabled=True):
    tool = FunctionTool(name=binding.name, description=binding.port.description,
                        params_json_schema=binding.model_input_schema(),
                        on_invoke_tool=invoke, strict_json_schema=False, is_enabled=is_enabled)
    # Preserve native optional fields/defaults. Native prepare validates input.
    # A Store/control failure must escape the SDK, not become a model-facing string.
    return set_function_tool_failure_error_function(tool, None)


async def run_tool(*, binding, arguments_json, task, store, files, active_calls=None):
    action_id = await store.create_action(task["work_id"], task["id"], binding.name, arguments_json)
    try:
        prepared = binding.prepare(loads(arguments_json), job_id=store.job_id,
                                   task=task, action_id=action_id)
    except (ValueError, TypeError, KeyError) as exc:
        ref = await store.fail_action(action_id, "prepare", str(exc) or type(exc).__name__)
        return {"status": "failed", "data": await store.read_result(ref), "result_ref": ref}
    await store.start_action(action_id, prepared)

    async def invoke_and_record():
        try:
            native = await binding.port.invoke(prepared)
        except (ExecutionEnded, StoreError):
            raise
        except Exception as exc:
            ref = await store.fail_action(action_id, "invoke", str(exc) or type(exc).__name__)
            return {"status": "failed", "data": await store.read_result(ref), "result_ref": ref}
        # File/Store failures are outside the native execution exception boundary.
        await files.register_completed(store)
        ref = await store.finish_action(action_id, native)
        return {"status": normalize_status(native)[0], "data": native, "result_ref": ref}

    invocation = asyncio.create_task(invoke_and_record())
    if active_calls is not None:
        active_calls.setdefault(task["id"], []).append(invocation)
    # Cancellation of a Runner must not abandon an already invoked native Tool,
    # its file writes or its actual return. Keep Page ownership until this settles.
    interrupted = None
    while True:
        try:
            reply = await asyncio.shield(invocation)
            break
        except asyncio.CancelledError as exc:
            if invocation.cancelled():
                raise
            interrupted = interrupted or exc
    if interrupted is not None:
        raise interrupted
    return reply


def make_query_tools(registry, store, *, is_enabled=True):
    tools = []
    for name in ("record_reader", "read_result"):
        binding = registry[name]

        async def invoke(ctx, arguments_json, binding=binding):
            ids = ctx.context
            if ids.job_id != store.job_id:
                raise StoreError("Manager query belongs to another job")
            await store.start_manager_query(ids.manager_call_id)
            try:
                try:
                    prepared = binding.port.prepare({"arguments": loads(arguments_json)}, {})
                except (ValueError, TypeError, KeyError) as exc:
                    return dumps({"status": "error", "error": str(exc)})
                result = await binding.port.invoke(prepared)
                return dumps(result)
            finally:
                await store.finish_manager_query(ids.manager_call_id)

        tools.append(_sdk_tool(binding, invoke, is_enabled=is_enabled))
    return tools


def make_executor_tools(registry, task, store, files, *, ensure_open=None, active_calls=None):
    check_open = ensure_open or store.ensure_execution_open
    result = []
    for name in task["execution"]["allowed_tools"]:
        binding = registry[name]

        async def invoke(ctx, arguments_json, binding=binding):
            check_open()
            reply = await run_tool(binding=binding, arguments_json=arguments_json,
                                   task=task, store=store, files=files, active_calls=active_calls)
            check_open()
            return await files.tool_output(binding.name, reply)

        result.append(_sdk_tool(binding, invoke))
    return result
