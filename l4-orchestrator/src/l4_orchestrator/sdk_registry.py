"""One native definition for manager assignment guidance and SDK Tool calls."""
from copy import deepcopy
from dataclasses import dataclass, replace
from importlib import import_module
from typing import Any, Mapping

from pydantic import TypeAdapter

from .ports import ExecutionPort


@dataclass(frozen=True)
class ToolBinding:
    name: str
    port: ExecutionPort
    input_type: Any
    uses_page: bool = False
    action_context: bool = False
    scoped_port: Any = None

    def model_input_schema(self):
        schema = deepcopy(TypeAdapter(self.input_type).json_schema())
        if self.action_context:
            for field in ("action_id", "tool"):
                schema["properties"].pop(field)
            schema["required"] = [f for f in schema.get("required", [])
                                  if f not in {"action_id", "tool"}]
            context = schema["$defs"]["ActionContext"]
            runtime = {"job_id", "scenario_id", "step_id"}
            context["properties"] = {k: v for k, v in context["properties"].items()
                                     if k not in runtime}
            context["required"] = [f for f in context.get("required", []) if f not in runtime]
        # All read_result alternatives are objects. Keep their native union and
        # fields; do not invent an enclosing SDK argument or move their members.
        schema.setdefault("type", "object")
        return schema

    def prepare(self, arguments, *, job_id, task, action_id):
        if type(arguments) is not dict:
            raise ValueError("Tool arguments must be a JSON object")
        native = deepcopy(arguments)
        if self.action_context:
            if "action_id" in native or "tool" in native:
                raise ValueError("action_id and tool are supplied by the runtime")
            context = native.get("context")
            if type(context) is not dict:
                raise ValueError("context must use the native Tool object shape")
            if {"job_id", "scenario_id", "step_id"} & context.keys():
                raise ValueError("Tracking IDs are supplied by the runtime")
            native.update(action_id=action_id, tool=self.name)
            context.update(job_id=job_id, scenario_id=task["id"], step_id=action_id)
        return self.port.prepare({"arguments": native}, task)


class ToolRegistry:
    def __init__(self, bindings):
        bindings = tuple(bindings)
        self._bindings = {b.name: b for b in bindings}
        if len(self._bindings) != len(bindings):
            raise ValueError("Duplicate Tool registration")
        if any(b.port.kind != "tool" for b in bindings):
            raise ValueError("Register native Tools; executor Agents are created by the runtime")

    def __contains__(self, name):
        return name in self._bindings

    def __getitem__(self, name):
        return self._bindings[name]

    def catalog(self):
        return {name: {"description": b.port.description,
                       "model_input_schema": b.model_input_schema()}
                for name, b in self._bindings.items()}

    def task_uses_page(self, task):
        execution = task["execution"]
        names = [execution["name"]] if execution["kind"] == "tool" else execution["allowed_tools"]
        return any(self[name].uses_page for name in names)

    def replacing(self, binding):
        return ToolRegistry([b for name, b in self._bindings.items() if name != binding.name]
                            + [binding])

    def for_task(self, task):
        return ToolRegistry([replace(b, port=b.scoped_port(task), scoped_port=None)
                             if b.scoped_port is not None else b for b in self._bindings.values()])


def store_reader_binding(store, *, max_list_items, max_data_bytes):
    from .storage.read_result_source import make_read_result_source
    from .tools.read_result import ReadResultInput, ReadResultTool

    def port(works=None):
        return ReadResultTool(make_read_result_source(store, allowed_work_ids=works),
            max_list_items=max_list_items, max_data_bytes=max_data_bytes).as_port()

    return ToolBinding("read_result", port(), ReadResultInput,
                       scoped_port=lambda task: port({task["work_id"]}))


_INPUTS = {
    "navigate": "NavigateInput", "get_page_state": "GetPageStateInput",
    "click": "ClickInput",
    "fill": "FillInput", "press_key": "PressKeyInput", "check": "CheckInput", "hover": "HoverInput",
    "go_back": "GoBackInput", "reload": "ReloadInput", "scroll": "ScrollInput",
    "select_option": "SelectOptionInput", "wait_for": "WaitForInput",
    "capture_screenshot": "CaptureScreenshotInput", "get_network_requests": "GetNetworkRequestsInput",
    "export_page": "ExportPageInput",
    "bash": "BashInput", "record_reader": "ReadRecordInput", "read_result": "ReadResultInput",
}


def register_native_tools(tools: Mapping[str, Any]) -> ToolRegistry:
    """Bind caller-created native instances. The caller owns Page/Bash/storage settings."""
    bindings = []
    for name, tool in tools.items():
        if name not in _INPUTS:
            raise ValueError(f"No native input definition registered for {name}")
        module = import_module(f".tools.{name}", __package__)
        browser = name not in {"bash", "record_reader", "read_result"}
        bindings.append(ToolBinding(name, tool.as_port(), getattr(module, _INPUTS[name]),
                                    uses_page=browser and name != "get_network_requests", action_context=browser))
    return ToolRegistry(bindings)
