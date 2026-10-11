import asyncio
import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

playwright = pytest.importorskip("playwright.async_api")

from l4_orchestrator.page_state import PageState
from l4_orchestrator.ports import Authorization
from l4_orchestrator.screenshot_storage import LocalScreenshotStore
from l4_orchestrator.tools.capture_screenshot import CaptureScreenshotTool
from test_navigate import site, with_page


HTML = """<!doctype html><style>html,body{margin:0;background:#ff0000}
#below{position:absolute;top:900px;background:blue;width:100%;height:200px}</style>
<div id="below">Below the viewport</div>"""


def action(state_id=None):
    return {"action_id": "shot-1", "tool": "capture_screenshot", "target": None,
            "params": {"full_page": False},
            "context": {"job_id": "controlled-check", "scenario_id": "screenshot",
                        "step_id": "observe", "state_id": state_id}}


async def setup(page, root):
    await page.set_viewport_size({"width": 320, "height": 180})
    await page.set_content(HTML)
    await page.evaluate("() => new Promise(requestAnimationFrame)")
    state = PageState(page, timeout_ms=3000)
    store = LocalScreenshotStore(root)
    return state, store, CaptureScreenshotTool(state, timeout_ms=3000, save_png=store.save_png)


async def decode_png(page, png):
    # Decode the real saved PNG through the browser; verify pixels, not just its signature.
    return await page.evaluate("""async data => {
        const image = new Image(); image.src = data; await image.decode();
        const canvas = document.createElement('canvas');
        canvas.width = image.width; canvas.height = image.height;
        const context = canvas.getContext('2d'); context.drawImage(image, 0, 0);
        return {width: image.width, height: image.height,
                pixel: Array.from(context.getImageData(5, 5, 1, 1).data)};
    }""", "data:image/png;base64," + base64.b64encode(png).decode())


def test_viewport_capture_without_dom_refresh_is_saved_and_can_be_decoded(site, tmp_path, monkeypatch):
    async def check(page):
        state, store, tool = await setup(page, tmp_path)

        async def no_refresh():
            pytest.fail("Screenshot must not refresh the PageState")

        monkeypatch.setattr(state, "refresh", no_refresh)
        first = await tool.execute(action())
        assert first["status"] == "success"
        assert first["before_state_id"] is first["after_state_id"] is None
        data = first["result"]
        png = await store.load_png(data["artifact_ref"], data["sha256"])
        assert await decode_png(page, png) == {"width": 320, "height": 180, "pixel": [255, 0, 0, 255]}
        meta = json.loads(next(tmp_path.glob("*/capture.json")).read_text(encoding="utf-8"))
        assert meta["capture"]["context"] == action()["context"]
        assert meta["capture"]["page_id"] == state.page_id == data["page_id"]
        assert meta["capture"]["captured_at"] == data["captured_at"]
        assert meta["byte_length"] == len(png) and meta["sha256"] == hashlib.sha256(png).hexdigest()
        second = await tool.execute(action())
        assert second["result"]["artifact_ref"] != data["artifact_ref"]
        assert len(list(tmp_path.glob("*/image.png"))) == 2
        assert not page.is_closed()
    asyncio.run(with_page(site, check))


def test_state_precondition_and_invalidation_during_capture(site, tmp_path, monkeypatch):
    async def check(page):
        state, store, tool = await setup(page, tmp_path)
        observed = await state.refresh()
        valid = await tool.execute(action(observed["state_id"]))
        assert valid["status"] == "success"
        assert valid["before_state_id"] == valid["after_state_id"] == observed["state_id"]
        wrong = await tool.execute(action("state-other-page"))
        assert wrong["error"]["code"] == "STATE_CHANGED" and wrong["result"] is None

        actual_capture = page.screenshot

        async def changing_capture(**kwargs):
            png = await actual_capture(**kwargs)
            state.invalidate()  # Notification arriving before acceptance of a captured image.
            return png

        monkeypatch.setattr(page, "screenshot", changing_capture)
        changed = await tool.execute(action(observed["state_id"]))
        assert changed["error"]["code"] == "STATE_CHANGED" and changed["after_state_id"] is None
        assert len(list(tmp_path.glob("*/image.png"))) == 1
        unconstrained = await tool.execute(action())
        assert unconstrained["status"] == "success"  # A stale DOM observation is not a capture prohibition.
        assert unconstrained["after_state_id"] is None
    asyncio.run(with_page(site, check))


def test_unsupported_timeout_closed_and_save_failure_are_distinct(site, tmp_path, monkeypatch):
    async def check(page):
        state, store, tool = await setup(page, tmp_path)
        full = action()
        full["params"]["full_page"] = True
        assert (await tool.execute(full))["error"]["code"] == "UNSUPPORTED_CAPTURE"
        for invalid in [dict(action(), target={"element_id": "e-1"}),
                        dict(action(), params={"full_page": "false"})]:
            with pytest.raises(ValidationError):
                await tool.execute(invalid)
        assert not list(tmp_path.iterdir())

        actual_capture = page.screenshot

        async def timeout(**kwargs):
            raise playwright.TimeoutError("Controlled screenshot timeout")

        monkeypatch.setattr(page, "screenshot", timeout)
        timed_out = await tool.execute(action())
        assert timed_out["status"] == "timeout" and timed_out["error"]["code"] == "ACTION_TIMEOUT"
        monkeypatch.setattr(page, "screenshot", actual_capture)

        async def broken_save(png, metadata):
            raise OSError("Controlled disk failure")

        failing = CaptureScreenshotTool(state, timeout_ms=3000, save_png=broken_save)
        failed = await failing.execute(action())
        assert failed["error"]["code"] == "ARTIFACT_SAVE_FAILED" and failed["result"] is None
        assert not list(tmp_path.iterdir())
        await page.close()
        assert (await tool.execute(action()))["error"]["code"] == "PAGE_CLOSED"
    asyncio.run(with_page(site, check))


def test_store_never_overwrites_and_cleans_partial_save(site, tmp_path, monkeypatch):
    async def check(page):
        _, store, tool = await setup(page, tmp_path)
        fixed_id = "a" * 32
        monkeypatch.setattr("l4_orchestrator.screenshot_storage.uuid4", lambda: SimpleNamespace(hex=fixed_id))
        first = await tool.execute(action())
        original = (tmp_path / fixed_id / "image.png").read_bytes()
        await page.evaluate("document.body.style.background = 'blue'")
        collision = await tool.execute(action())
        assert collision["error"]["code"] == "ARTIFACT_SAVE_FAILED"
        assert (tmp_path / fixed_id / "image.png").read_bytes() == original
        assert await store.load_png(first["result"]["artifact_ref"], first["result"]["sha256"]) == original

        monkeypatch.setattr("l4_orchestrator.screenshot_storage.uuid4", lambda: SimpleNamespace(hex="b" * 32))
        original_open = Path.open

        def failing_metadata(path, *args, **kwargs):
            if path.name == "capture.json":
                raise OSError("Controlled metadata failure")
            return original_open(path, *args, **kwargs)

        monkeypatch.setattr(Path, "open", failing_metadata)
        assert (await tool.execute(action()))["error"]["code"] == "ARTIFACT_SAVE_FAILED"
        assert not (tmp_path / ("b" * 32)).exists()
        assert (tmp_path / fixed_id / "image.png").read_bytes() == original
    asyncio.run(with_page(site, check))




def test_one_sdk_tool_call_delivers_same_png_to_executor_without_store_base64(site, tmp_path):
    from l4_orchestrator.sdk_files import FileConnections
    from l4_orchestrator.sdk_registry import register_native_tools, store_reader_binding
    from l4_orchestrator.tools.record_reader import RecordReader
    from test_sdk_runtime import ScriptModel, execute, report, review, setup as sdk_setup, task, tool_call, turn, work

    async def check(page):
        _, screenshots, native_tool = await setup(page, tmp_path)
        store, _, io, publisher = sdk_setup()
        registry = register_native_tools({"capture_screenshot": native_tool,
            "record_reader": RecordReader({}, max_data_bytes=4096)}).replacing(
            store_reader_binding(store, max_list_items=10, max_data_bytes=4096))
        manager = ScriptModel(turn(works=[work(["capture_screenshot"])], tasks=[task(execution={
            "kind": "agent", "instruction": "한 번 촬영한 화면을 확인", "allowed_tools": ["capture_screenshot"],
            "input_refs": []})], review=review("T1")), turn(finish=report("report:T1")))

        async def inspect_image(call):
            parts = [item for item in call["input"] if item.get("type") == "function_call_output"][-1]["output"]
            assert [part["type"] for part in parts] == ["input_text", "input_image"]
            native = json.loads(parts[0]["text"])["data"]
            data = native["result"]
            png = base64.b64decode(parts[1]["image_url"].split(",", 1)[1], validate=True)
            assert png == await screenshots.load_png(data["artifact_ref"], data["sha256"])
            assert await decode_png(page, png) == {"width": 320, "height": 180, "pixel": [255, 0, 0, 255]}
            assert native == await store.read_result("result:ACT1")
            return report("result:ACT1")

        executor = ScriptModel(tool_call("capture_screenshot", {
            "target": None, "params": {"full_page": False}, "context": {"state_id": None}}, "capture"), inspect_image)
        await execute(manager, executor, setup_values=(store, registry, io, publisher),
            files=FileConnections(producers=(screenshots,), screenshots=screenshots))
        actions = [record for record in store.snapshot_records() if record.record_key.startswith("ACTION#")]
        assert len(actions) == 1 and len(executor.calls) == 2
        assert len(list(tmp_path.glob("*/image.png"))) == 1
        serialized = json.dumps([record.body() for record in store.snapshot_records()])
        assert "base64" not in serialized and "iVBORw0" not in serialized
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("problem", ["missing", "changed", "wrong_digest"])
def test_sdk_image_delivery_failures_do_not_return_ref_only_or_recapture(site, tmp_path, problem):
    from l4_orchestrator.sdk_files import FileConnections, ImageDeliveryError

    async def check(page):
        _, store, tool = await setup(page, tmp_path)
        captured = await tool.execute(action())
        reply = {"status": "success", "data": captured, "result_ref": "result:ACT1"}
        digest = captured["result"]["sha256"]
        image_path = next(tmp_path.glob("*/image.png"))
        if problem == "missing":
            image_path.unlink()
        elif problem == "changed":
            image_path.write_bytes(b"changed PNG")
        elif problem == "wrong_digest":
            reply["data"]["result"]["sha256"] = "0" * 64
        before = deepcopy(reply)
        with pytest.raises(ImageDeliveryError) as caught:
            await FileConnections(screenshots=store).tool_output("capture_screenshot", reply)
        assert reply == before
        assert "base64" not in str(caught.value) and digest not in str(caught.value)
        assert len(list(tmp_path.glob("*/capture.json"))) == 1
    asyncio.run(with_page(site, check))


def test_storage_root_is_explicit_and_sdk_tool_failure_has_no_image(tmp_path):
    from l4_orchestrator.sdk_files import FileConnections

    with pytest.raises(ValueError):
        LocalScreenshotStore(Path("relative-default-not-allowed"))
    with pytest.raises(FileNotFoundError):
        LocalScreenshotStore(tmp_path / "missing-directory")
    failed = {"tool": "capture_screenshot", "status": "failed", "result": None,
              "error": {"code": "ARTIFACT_SAVE_FAILED"}}
    reply = {"status": "failed", "data": failed, "result_ref": "result:ACT1"}
    output = asyncio.run(FileConnections().tool_output("capture_screenshot", reply))
    assert isinstance(output, str) and json.loads(output) == reply
