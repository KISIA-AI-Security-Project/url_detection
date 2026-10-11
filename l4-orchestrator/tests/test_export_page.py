from page_query_support import make_query_tool
from sdk_tool_checks import run_native_steps
"""Real Page -> complete HTML file -> real Bash -> subsequent flow input."""
import asyncio
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

pytest.importorskip("playwright.async_api")

from l4_orchestrator.elements import ElementRegistry
from l4_orchestrator.page_events import PageEvents
from l4_orchestrator.page_export_storage import LocalPageExportStore
from l4_orchestrator.page_state import PageState
from l4_orchestrator.ports import Authorization
from l4_orchestrator.tools.click import ClickTool
from l4_orchestrator.tools.export_page import ExportPageInput, ExportPageTool, _COLLECT
from test_bash import bash_path, make_tool as make_bash, python_command
from test_click import action as click_action
from test_interactable_elements import query as elements_query
from test_navigate import site, with_page


def action(state_id=None):
    return {"action_id": "export-check", "tool": "export_page", "target": None, "params": {},
            "context": {"job_id": "local-check", "scenario_id": "html-export",
                        "step_id": "save-source", "state_id": state_id}}


def make_tool(state, store, **overrides):
    values = dict(timeout_ms=3000, max_html_bytes=20000, save_html=store.save_html)
    return ExportPageTool(state, **{**values, **overrides})


@pytest.mark.parametrize("doctype", ["<!DOCTYPE html>", ""])
def test_exact_current_html_and_metadata_without_reloading(site, tmp_path, doctype):
    async def check(page):
        await page.goto(site)
        await page.set_content(doctype + '<title>계정 확인</title><p hidden>숨김 근거</p>'
            '<form action="/verify"><input value="original"></form>'
            '<script type="application/json">{"embedded":"preserved"}</script><div id="host"></div>')
        await page.evaluate("""() => {
            document.querySelector('input').value='live-value-only';
            document.querySelector('#host').attachShadow({mode:'open'}).innerHTML='<p>shadow-internal</p>';
            window.sessionProof = 'same-page'; document.cookie = 'export_session=kept';
        }""")
        source = await page.content()
        state = PageState(page, timeout_ms=3000)
        store = LocalPageExportStore(tmp_path)
        response = await make_tool(state, store).execute(action())
        assert response["status"] == "success", response
        data = response["result"]
        raw = (tmp_path / data["relative_path"]).read_bytes()
        assert raw == source.encode("utf-8")
        assert ("<!DOCTYPE html>" in raw.decode("utf-8")) is bool(doctype)
        assert "숨김 근거" in raw.decode("utf-8") and b'{"embedded":"preserved"}' in raw
        assert b"shadow-internal" not in raw and b"live-value-only" not in raw
        assert data["size_bytes"] == len(raw) and data["sha256"] == hashlib.sha256(raw).hexdigest()
        assert data["url"] == site + "/" and data["page_id"] == state.page_id
        assert data["state_id"] == response["after_state_id"] == state.read()["state_id"]
        assert data["observation_scope"] == "main_document_light_dom"
        assert data["content_type"] == "text/html; charset=utf-8" and "html" not in data
        descriptor = store.completed_file(data["file_ref"])
        assert descriptor.local_path == tmp_path / data["relative_path"]
        assert descriptor.size_bytes == len(raw) and descriptor.sha256 == data["sha256"]
        metadata = json.loads(descriptor.source_metadata_json)
        assert metadata["context"] == action()["context"] and metadata["state_id"] == data["state_id"]
        assert metadata["observed_at"] == data["observed_at"]
        repeated = await make_tool(state, store).execute(action(data["state_id"]))
        assert repeated["status"] == "success" and repeated["after_state_id"] == data["state_id"]
        assert repeated["result"]["file_ref"] != data["file_ref"] and len(store.completed_files()) == 2
        assert await page.content() == source and await page.evaluate("window.sessionProof") == "same-page"
        assert "export_session=kept" in await page.evaluate("document.cookie")
        assert len(page.context.pages) == 1
    asyncio.run(with_page(site, check))


def test_whole_utf8_size_limit_and_stale_state_never_save_partial_html(site, tmp_path):
    async def check(page):
        await page.set_content("<!doctype html><p>한글🙂</p>")
        size = len((await page.content()).encode("utf-8"))
        state = PageState(page, timeout_ms=3000)
        store = LocalPageExportStore(tmp_path)
        too_big = await make_tool(state, store, max_html_bytes=size - 1).execute(action())
        assert too_big["error"]["code"] == "HTML_TOO_LARGE" and too_big["result"] is None
        assert not list(tmp_path.iterdir()) and not store.completed_files()
        exact = await make_tool(state, store, max_html_bytes=size).execute(action())
        assert exact["status"] == "success" and exact["result"]["size_bytes"] == size
        old = exact["after_state_id"]
        await page.evaluate("document.querySelector('p').textContent='변경'")
        stale = await make_tool(state, store).execute(action(old))
        assert stale["error"]["code"] == "STATE_CHANGED" and stale["result"] is None
        wrong = await make_tool(state, store).execute(action("another-page-state"))
        assert wrong["error"]["code"] == "STATE_CHANGED"
        assert len(store.completed_files()) == len(list(tmp_path.iterdir())) == 1
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("change, code", [("dom", "STATE_CHANGED"), ("navigate", "STATE_CHANGED"),
                                        ("close", "PAGE_CLOSED")])
def test_change_during_collection_saves_nothing_and_does_not_retry(site, tmp_path, monkeypatch, change, code):
    async def check(page):
        await page.goto(site)
        state, store = PageState(page, timeout_ms=3000), LocalPageExportStore(tmp_path)
        original, calls = state.observe, []

        async def change_after_observing(expected):
            snapshot = await original(expected)
            calls.append(True)
            if change == "dom":
                await page.evaluate("document.body.append('Changed')")
            elif change == "navigate":
                await page.goto(site + "/destination")
            else:
                await page.close()
            return snapshot

        monkeypatch.setattr(state, "observe", change_after_observing)
        response = await make_tool(state, store).execute(action())
        assert response["status"] == "failed" and response["error"]["code"] == code
        assert response["result"] is None and response["after_state_id"] is None
        assert len(calls) == 1 and not list(tmp_path.iterdir()) and not store.completed_files()
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("change", ["navigate", "close"])
def test_change_during_save_keeps_captured_file_but_not_current_action_state(site, tmp_path, change):
    async def check(page):
        await page.goto(site)
        await page.set_content("<!doctype html><p>이미 확보한 문서</p>")
        source = (await page.content()).encode("utf-8")
        state, store = PageState(page, timeout_ms=3000), LocalPageExportStore(tmp_path)

        async def changed_save(raw, metadata):
            if change == "navigate":
                await page.goto(site + "/destination")
            else:
                await page.close()
            return await store.save_html(raw, metadata)

        response = await make_tool(state, store, save_html=changed_save).execute(action())
        assert response["status"] == "success", response
        data = response["result"]
        assert response["after_state_id"] is None and data["state_id"]
        assert data["url"] == site + "/" and (tmp_path / data["relative_path"]).read_bytes() == source
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("ending", ["timeout", "cancel"])
def test_unfinished_read_does_not_save_or_retry(site, tmp_path, monkeypatch, ending):
    async def check(page):
        state, store = PageState(page, timeout_ms=3000), LocalPageExportStore(tmp_path)
        snapshot = await state.refresh()
        original = page.evaluate
        entered, calls = asyncio.Event(), []

        async def delayed(expression, arg=None):
            if expression == _COLLECT:
                calls.append(True)
                entered.set()
                await asyncio.Event().wait()  # Inject an unresponsive browser transport.
            return await original(expression, arg)

        monkeypatch.setattr(page, "evaluate", delayed)
        tool = make_tool(state, store, timeout_ms=100 if ending == "timeout" else 3000)
        pending = asyncio.create_task(tool.execute(action(snapshot["state_id"])))
        await entered.wait()
        if ending == "cancel":
            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pending
        else:
            response = await pending
            assert response["status"] == "timeout" and response["error"]["code"] == "ACTION_TIMEOUT"
            assert response["result"] is None
        assert len(calls) == 1 and not list(tmp_path.iterdir()) and not store.completed_files()
    asyncio.run(with_page(site, check))


def test_save_error_and_mismatched_receipt_are_not_success(site, tmp_path):
    async def check(page):
        state, store = PageState(page, timeout_ms=3000), LocalPageExportStore(tmp_path)

        async def failing(raw, metadata):
            raise OSError("Controlled disk error")

        async def wrong_receipt(raw, metadata):
            saved = await store.save_html(raw, metadata)
            return replace(saved, sha256="0" * 64)

        for save in (failing, wrong_receipt):
            response = await make_tool(state, store, save_html=save).execute(action())
            assert response["status"] == "failed" and response["error"]["code"] == "ARTIFACT_SAVE_FAILED"
            assert response["result"] is None and response["after_state_id"] is None
        # Receipt verification cannot delete a file owned by an arbitrary saver.
        assert len(store.completed_files()) == 1
    asyncio.run(with_page(site, check))


def test_storage_collision_and_write_failure_preserve_existing_files(tmp_path, monkeypatch):
    store = LocalPageExportStore(tmp_path)
    fixed = "a" * 32
    monkeypatch.setattr("l4_orchestrator.page_export_storage.uuid4", lambda: SimpleNamespace(hex=fixed))
    first = asyncio.run(store.save_html(b"<html>original</html>", {}))
    with pytest.raises(FileExistsError):
        asyncio.run(store.save_html(b"<html>replacement</html>", {}))
    assert (tmp_path / first.relative_path).read_bytes() == b"<html>original</html>"
    monkeypatch.setattr("l4_orchestrator.page_export_storage.uuid4", lambda: SimpleNamespace(hex="b" * 32))
    original_open = Path.open

    class FailedWrite:
        def __init__(self, path):
            self.handle = original_open(path, "xb")
        def __enter__(self):
            return self
        def write(self, raw):
            self.handle.write(raw[:4])
            raise OSError("Controlled write failure after a prefix")
        def __exit__(self, *args):
            self.handle.close()

    def failing_open(path, mode="r", *args, **kwargs):
        if mode == "xb" and path.name == "b" * 32 + ".html":
            return FailedWrite(path)
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", failing_open)
    with pytest.raises(OSError):
        asyncio.run(store.save_html(b"<html>incomplete</html>", {}))
    assert [path.name for path in tmp_path.iterdir()] == [first.relative_path]
    assert len(store.completed_files()) == 1


def test_repeated_cancellation_waits_for_disk_and_retains_completed_descriptor(tmp_path, monkeypatch):
    async def check():
        store = LocalPageExportStore(tmp_path)
        original, started, release = store._write, threading.Event(), threading.Event()
        raw, metadata = "<!DOCTYPE html><p>취소 시 저장</p>".encode(), {"page_id": "actual-test-page"}

        def delayed(path, content):
            started.set()
            if not release.wait(5):
                raise RuntimeError("Test did not release the disk writer")
            original(path, content)

        monkeypatch.setattr(store, "_write", delayed)
        pending = asyncio.create_task(store.save_html(raw, metadata))
        try:
            assert await asyncio.to_thread(started.wait, 3)
            pending.cancel()
            await asyncio.sleep(0)
            pending.cancel()
            await asyncio.sleep(0)
            assert not pending.done() and not store.completed_files()
        finally:
            release.set()
        with pytest.raises(asyncio.CancelledError):
            await pending
        completed, = store.completed_files()
        assert completed.local_path.read_bytes() == raw
        assert completed.sha256 == hashlib.sha256(raw).hexdigest()
        assert json.loads(completed.source_metadata_json) == metadata
    asyncio.run(check())


def test_invalid_input_and_settings_cannot_select_a_file_path(tmp_path):
    store = LocalPageExportStore(tmp_path)
    for extra in ({"target": {"path": "../outside.html"}}, {"params": {"format": "html"}},
                  {"params": {"path": "chosen.html"}}):
        with pytest.raises(ValidationError):
            ExportPageInput.model_validate({**action(), **extra})
    for settings in ({"timeout_ms": 0}, {"max_html_bytes": True}, {"save_html": None}):
        with pytest.raises((ValueError, TypeError)):
            make_tool(None, store, **settings)
    with pytest.raises(ValueError):
        LocalPageExportStore(Path("relative"))
    with pytest.raises(FileNotFoundError):
        LocalPageExportStore(tmp_path / "missing")
    assert not list(tmp_path.iterdir())


def test_click_export_bash_and_next_sdk_input_use_the_same_file(site, tmp_path, bash_path):
    from l4_orchestrator.sdk_files import FileConnections

    async def check(page):
        await page.goto(site)
        await page.set_content("""<!doctype html><base href="/account/">
            <button type="button" onclick="document.querySelector('form').setAttribute('action','verify');
                document.querySelector('p').textContent='확인 단계'; window.clicks++">Continue</button>
            <p>처음 단계</p><form action="initial"><input name="email"></form>
            <script type="application/json" src="/scripts/form.js"></script>""")
        await page.evaluate("window.clicks=0;document.cookie='export_flow=kept'")
        state = PageState(page, timeout_ms=3000)
        registry = ElementRegistry(state, timeout_ms=3000)
        controls = (await make_query_tool(registry.state, elements=registry).execute(elements_query()))["result"]
        clicked = await ClickTool(registry, timeout_ms=3000,
            page_events=PageEvents(state, on_event=lambda *args: None)).execute(
                click_action(controls["elements"][0]["element_id"], controls["state_id"]))
        assert clicked["status"] == "success", clicked
        source = await page.content()
        store = LocalPageExportStore(tmp_path)

        def extract(previous):
            exported = previous[-1]
            assert exported["status"] == "success", exported
            name = exported["result"]["relative_path"]
            code = f"""import hashlib, json
from html.parser import HTMLParser
from pathlib import Path
class Extract(HTMLParser):
    def __init__(self):
        super().__init__(); self.forms=[]; self.scripts=[]
    def handle_starttag(self, tag, attrs):
        attrs=dict(attrs)
        if tag=='form': self.forms.append(attrs.get('action'))
        if tag=='script': self.scripts.append(attrs.get('src'))
raw=Path({name!r}).read_bytes()
p=Extract(); p.feed(raw.decode('utf-8'))
print(json.dumps({{'forms':p.forms,'scripts':p.scripts,'sha256':hashlib.sha256(raw).hexdigest(),
                  'size_bytes':len(raw)}}, ensure_ascii=False))
"""
            return {"command": python_command(code), "timeout_ms": 5000}

        proof = await run_native_steps({"export_page": make_tool(state, store),
            "bash": make_bash(bash_path, tmp_path)}, [("export_page", action()), ("bash", extract)],
            files=FileConnections(producers=(store,)))
        exported, reply = proof.results
        data = exported["result"]
        raw = (tmp_path / data["relative_path"]).read_bytes()
        assert raw == source.encode("utf-8")
        assert reply["status"] == "success" and reply["exit_code"] == 0, reply
        assert json.loads(reply["stdout"]) == {
            "forms": ["verify"], "scripts": ["/scripts/form.js"],
            "sha256": data["sha256"], "size_bytes": len(raw)}
        assert await page.content() == source and await page.evaluate("window.clicks") == 1
        assert "export_flow=kept" in await page.evaluate("document.cookie") and len(page.context.pages) == 1
        (tmp_path / "sdk-evidence.json").write_text(json.dumps({
            "source_html_after_click": source, "prepared_inputs": proof.prepared_inputs,
            "results": proof.results, "actual_model_inputs": proof.model_inputs,
            "source_and_file_unchanged": True}, ensure_ascii=False, indent=2), encoding="utf-8")
    asyncio.run(with_page(site, check))
