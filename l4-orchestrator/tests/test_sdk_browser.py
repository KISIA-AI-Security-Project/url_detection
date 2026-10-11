"""SDK -> native browser/Bash -> complete files -> Store -> publisher readback.

Models are scripted at the SDK Model boundary; this is not live model judgment
or an AWS deployment. Browser, PNG, HTML, Bash and SDK execution are real.
"""
import asyncio
import base64
import hashlib
import json

from l4_orchestrator.json_values import dumps
from l4_orchestrator.network_capture import NetworkCapture
from l4_orchestrator.network_storage import LocalNetworkStore
from l4_orchestrator.page_events import PageEvents
from l4_orchestrator.page_export_storage import LocalPageExportStore
from l4_orchestrator.page_state import PageState
from l4_orchestrator.ports import Authorization
from l4_orchestrator.screenshot_storage import LocalScreenshotStore
from l4_orchestrator.sdk_files import FileConnections
from l4_orchestrator.sdk_registry import register_native_tools, store_reader_binding
from l4_orchestrator.storage.aws_reader import AwsRecordReader
from l4_orchestrator.tools.capture_screenshot import CaptureScreenshotTool
from l4_orchestrator.tools.export_page import ExportPageTool
from l4_orchestrator.page_content import PageContentReader
from l4_orchestrator.elements import ElementRegistry
from l4_orchestrator.tools.get_page_state import GetPageStateTool
from l4_orchestrator.tools.get_network_requests import GetNetworkRequestsTool
from l4_orchestrator.tools.navigate import NavigateTool
from l4_orchestrator.tools.record_reader import RecordReader
from test_bash import bash_path, make_tool as make_bash, python_command
from test_navigate import site, with_page
from test_sdk_runtime import ScriptModel, body, execute, report, review, setup, task, tool_call, turn, work


def arguments(params=None):
    return {"target": None, "params": params or {}, "context": {"state_id": None}}


def last_tool_reply(call):
    outputs = [i for i in call["input"] if i.get("type") == "function_call_output"]
    output = outputs[-1]["output"]
    if isinstance(output, list):
        output = next(i["text"] for i in output if i.get("type") == "input_text")
    return json.loads(output)


def test_existing_tools_run_under_sdk_and_publish_exact_files(site, tmp_path, bash_path):
    async def check(page):
        store, _, io, publisher = setup()
        record_reader = RecordReader({}, max_data_bytes=20000)
        screenshots, exports = LocalScreenshotStore(tmp_path), LocalPageExportStore(tmp_path)
        network_files = LocalNetworkStore(tmp_path, record_reader, max_record_bytes=30000)
        state = PageState(page, timeout_ms=3000)
        events = PageEvents(state, on_event=lambda *args: None)
        capture = NetworkCapture(state, page_events=events, save_record=network_files.save,
            max_requests=20, max_body_bytes=20000, max_total_body_bytes=50000,
            capture_timeout_ms=3000, response_body_types={"document"})
        native = {
            "navigate": NavigateTool(page, timeout_ms=3000, authorize_url=lambda url:
                                      Authorization(url.startswith(site + "/"), "local server")),
            "get_page_state": GetPageStateTool(state, elements=ElementRegistry(state, timeout_ms=3000),
                content=PageContentReader(state, timeout_ms=3000, max_text_bytes=10000,
                                          max_links=10, max_links_bytes=10000)),
            "capture_screenshot": CaptureScreenshotTool(state, timeout_ms=3000, save_png=screenshots.save_png),
            "export_page": ExportPageTool(state, timeout_ms=3000, max_html_bytes=20000, save_html=exports.save_html),
            "get_network_requests": GetNetworkRequestsTool(capture, max_return_items=10),
            "bash": make_bash(bash_path, tmp_path), "record_reader": record_reader,
        }
        registry = register_native_tools(native).replacing(store_reader_binding(
            store, max_list_items=10, max_data_bytes=20000))
        files = FileConnections(producers=(screenshots, exports, network_files),
                                close_callbacks=(capture.close,), screenshots=screenshots)
        first = task(execution={"kind": "tool", "name": "navigate", "arguments_json": dumps({
            "target": {"url": site + "/"}, "params": {}, "context": {"state_id": None}})})
        allowed = ["get_page_state", "export_page", "bash", "capture_screenshot",
                   "get_network_requests", "read_result"]
        agent_task = task("T2", execution={"kind": "agent", "instruction": "같은 Page의 본문과 파일 확인",
            "allowed_tools": allowed, "input_refs": ["result:ACT1"]})
        manager = ScriptModel(turn(works=[work(["navigate"] + allowed)], tasks=[first], review=review("T1")),
            turn(tasks=[agent_task], review=review("T2")), turn(finish=report("report:T2")))

        def run_bash(call):
            saved = last_tool_reply(call)["data"]["result"]
            command = python_command("from pathlib import Path; print(Path(" + repr(saved["relative_path"])
                                     + ").read_text(encoding='utf-8'))")
            return tool_call("bash", {"command": command, "timeout_ms": 3000}, "bash-read")

        def after_bash(call):
            assert "Loaded" in last_tool_reply(call)["data"]["stdout"]
            return tool_call("capture_screenshot", arguments(), "screenshot")

        def after_image(call):
            output = [i for i in call["input"] if i.get("type") == "function_call_output"][-1]["output"]
            pixels = next(i["image_url"] for i in output if i.get("type") == "input_image")
            png = base64.b64decode(pixels.split(",", 1)[1])
            assert png.startswith(b"\x89PNG\r\n\x1a\n")
            image = last_tool_reply(call)["data"]["result"]
            assert hashlib.sha256(png).hexdigest() == image["sha256"]
            return tool_call("get_network_requests", arguments({"limit": 10}), "network")

        def finish_agent(call):
            assert last_tool_reply(call)["data"]["status"] == "ok"
            return report("result:ACT4")

        executor = ScriptModel(tool_call("get_page_state", arguments(), "state"),
            tool_call("get_page_state", arguments({"include": ["text", "links"]}), "content"),
            tool_call("export_page", arguments(), "export"), run_bash, after_bash, after_image,
            tool_call("read_result", {"kind": "task", "id": "T2", "limit": 10}, "read-actions"), finish_agent)
        await execute(manager, executor, setup_values=(store, registry, io, publisher), files=files)
        descriptors = screenshots.completed_files() + exports.completed_files() + network_files.completed_files()
        assert screenshots.completed_files() and exports.completed_files() and network_files.completed_files()
        reader = AwsRecordReader(io)
        for completed in descriptors:
            fetched = await reader.file_bytes(await reader.item(store.job_id, "FILE#" + completed.file_ref))
            assert fetched == completed.local_path.read_bytes()
            assert hashlib.sha256(fetched).hexdigest() == completed.sha256
        actions = [r.body() for r in store.snapshot_records() if r.record_key.startswith("ACTION#")]
        assert len(actions) == 8 and all(a["status"] == "success" for a in actions)
        assert actions[1]["tool_name"] == "get_page_state"
        assert json.loads(actions[1]["arguments_json"]) == arguments()
        assert json.loads(actions[1]["prepared_input_json"])["context"] == {
            "state_id": None, "job_id": store.job_id, "scenario_id": "T2", "step_id": "ACT2"}
        assert await reader.body(await reader.item(store.job_id, "RESULT#result:ACT4")) == await store.read_result("result:ACT4")
        assert (await reader.item(store.job_id, "META"))["status"] == "completed"
        assert len(page.context.pages) == 1 and page.url == site + "/"
        evidence = {
            "scope": "actual SDK, local browser/Bash/files; scripted Model and memory AWS IO",
            "manager_inputs": [c["input"] for c in manager.calls],
            "executor_inputs": [c["input"] for c in executor.calls],
            "records": [{"record_key": r.record_key, "body": r.body()} for r in store.snapshot_records()],
            "files": [d.public_metadata() for d in descriptors],
            "published_meta": await reader.item(store.job_id, "META"),
        }
        (tmp_path / "sdk-evidence.json").write_text(dumps(evidence), encoding="utf-8")
    asyncio.run(with_page(site, check))
