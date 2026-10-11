"""Compare caller Builder/Judgment and the captured PNG with actual SDK input."""
import asyncio
import base64
import hashlib
import json

import pytest

from l4_orchestrator.page_state import PageState
from l4_orchestrator.screenshot_storage import LocalScreenshotStore
from l4_orchestrator.sdk_files import FileConnections
from l4_orchestrator.sdk_runtime import run_l4
from l4_orchestrator.sdk_types import ExecutionLimits
from l4_orchestrator.storage.aws_reader import AwsRecordReader
from l4_orchestrator.tools.capture_screenshot import CaptureScreenshotTool
from test_navigate import site, with_page
from test_sdk_runtime import RUN_CONFIG, ScriptModel, setup, turn


@pytest.mark.parametrize("manager_calls", [1, 3])
def test_first_manager_receives_same_builder_judgment_and_saved_png(site, tmp_path, manager_calls):
    async def check(page):
        await page.goto(site + "/", wait_until="domcontentloaded")
        screenshots = LocalScreenshotStore(tmp_path.resolve())
        capture = CaptureScreenshotTool(PageState(page, timeout_ms=3000), timeout_ms=3000,
                                        save_png=screenshots.save_png)
        reply = await capture.execute({"action_id": "initial-screen", "tool": "capture_screenshot",
            "target": None, "params": {}, "context": {"job_id": "sdk-local",
            "scenario_id": "initial-input", "step_id": "initial-screen", "state_id": None}})
        assert reply["status"] == "success"
        image = reply["result"]
        png = await screenshots.load_png(image["artifact_ref"], image["sha256"])
        builder = {"builder_context": "동일 Builder 본문\n관측 범위와 한계는 그대로 유지"}
        judgment = {"verdict": "UNKNOWN", "decision_notes": ["기존 판단을 그대로 전달"]}
        final = {"summary": "첫 입력 확인", "findings": [], "limits": []}
        store, registry, io, publisher = setup()
        manager = ScriptModel(turn(finish=final))
        await run_l4(job_id=store.job_id, initial_findings=builder, previous_judgment=judgment,
            initial_screenshot=image, store=store, publisher=publisher, registry=registry,
            model_name=manager, executor_model=ScriptModel(),
            execution_limits=ExecutionLimits(None, manager_calls, 2, None, None),
            files=FileConnections(producers=(screenshots,), screenshots=screenshots), run_config=RUN_CONFIG)
        content = manager.calls[0]["input"][-1]["content"]
        actual = json.loads(content[0]["text"])
        assert actual["initial_findings"] == builder and actual["previous_judgment"] == judgment
        assert actual["initial_screenshot"] == image
        assert content[1]["type"] == "input_image"
        transmitted = base64.b64decode(content[1]["image_url"].split(",", 1)[1])
        assert transmitted == png and hashlib.sha256(transmitted).hexdigest() == image["sha256"]
        reader = AwsRecordReader(io)
        saved = await reader.file_bytes(await reader.item(store.job_id, "FILE#" + image["artifact_ref"]))
        assert saved == png
        assert not [r for r in store.snapshot_records() if r.record_key.startswith("ACTION#")]

    asyncio.run(with_page(site, check))
