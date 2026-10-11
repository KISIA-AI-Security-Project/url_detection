from page_query_support import make_query_tool
from sdk_tool_checks import run_native_steps
import asyncio
import base64
from copy import deepcopy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from queue import Queue
from threading import Event as ThreadEvent, Thread
import time

import pytest
from pydantic import ValidationError

pytest.importorskip("playwright.async_api")
from playwright.async_api import Error, Request, Response

from l4_orchestrator.elements import ElementRegistry
from l4_orchestrator.network_capture import NetworkCapture
from l4_orchestrator.network_storage import LocalNetworkStore, SavedNetworkRecord
from l4_orchestrator.page_events import PageEvents
from l4_orchestrator.page_state import PageState
from l4_orchestrator.ports import Authorization
from l4_orchestrator.tools.click import ClickTool
from l4_orchestrator.tools.get_network_requests import GetNetworkRequestsInput, GetNetworkRequestsTool
from l4_orchestrator.tools.record_reader import RecordReader, RecordSource
from test_click import action as click_action
from test_interactable_elements import query
from test_navigate import with_page


API_BODY = b'{ "accepted": true, "large_number": 9007199254740993 }\n'
BINARY = b'\x00\xff\x80abc'
HTML = b'''<!doctype html><title>Network check</title><input aria-label="Value"><button>Send</button>
<script>document.querySelector('button').onclick=()=>{window.finished=false;
fetch('/api',{method:'POST',headers:{'Content-Type':'application/json'},
body:JSON.stringify({value:document.querySelector('input').value})})
.then(r=>r.text()).then(()=>window.finished=true)};</script>'''


@pytest.fixture(scope="module")
def network_site():
    received = Queue()

    class Handler(BaseHTTPRequestHandler):
        def reply(self, status, body, content_type="text/plain"):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", "first=1; Path=/")
            self.send_header("Set-Cookie", "second=2; Path=/")
            self.end_headers()
            try:
                self.wfile.write(body)
            except OSError:
                pass

        def do_GET(self):
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/destination")
                self.send_header("Content-Length", "0")
                self.end_headers()
            elif self.path == "/":
                self.reply(200, HTML, "text/html; charset=utf-8")
            elif self.path in {"/slow", "/hold"}:
                time.sleep(0.3 if self.path == "/slow" else 0.8)
                self.reply(200, API_BODY, "application/json")
            elif self.path == "/empty":
                self.reply(200, b"")
            elif self.path == "/large":
                self.reply(200, b"x" * 2048)
            elif self.path == "/binary":
                self.reply(200, BINARY, "application/octet-stream")
            else:
                self.reply(404 if self.path == "/missing" else 200, API_BODY, "application/json")

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            received.put({"path": self.path, "body": body})
            self.reply(200, API_BODY, "application/json")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}", received
    server.shutdown()
    server.server_close()
    thread.join()


def action(*, after=0, capture_id=None, limit=20):
    return {"action_id": "network-query", "tool": "get_network_requests", "target": None,
            "params": {"after_sequence": after, "capture_id": capture_id, "limit": limit},
            "context": {"job_id": "local-check", "scenario_id": "network", "step_id": "read", "state_id": None}}


def connected(page, tmp_path, *, state=None, save=None, max_requests=40, max_body_bytes=8192,
              max_total_body_bytes=65536, body_types=None, timeout_ms=1500):
    state = state or PageState(page, timeout_ms=3000)
    reader = RecordReader({}, max_data_bytes=65536)
    store = LocalNetworkStore(tmp_path, reader, max_record_bytes=131072)
    events = PageEvents(state, on_event=lambda event, event_page: None)
    capture = NetworkCapture(state, page_events=events, save_record=save or store.save,
                             max_requests=max_requests, max_body_bytes=max_body_bytes,
                             max_total_body_bytes=max_total_body_bytes, capture_timeout_ms=timeout_ms,
                             response_body_types={"document", "fetch", "xhr"} if body_types is None else body_types)
    return capture, GetNetworkRequestsTool(capture, max_return_items=40), reader, store


async def rows(tool, **params):
    result = await tool.execute(action(**params))
    assert result["status"] == "success", result
    return result["result"]


async def fetch(page, path, *, body=None):
    return await page.evaluate("async ({path,body}) => {const r=await fetch(path,body===null?{}:{method:'POST',body}); await r.arrayBuffer(); return r.status}",
                               {"path": path, "body": body})


async def ready(capture):
    assert await capture.flush(timeout_ms=4000)


def detail(reader, item):
    result = reader.read({"record_ref": item["record_ref"], "pointer": ""})
    assert result["status"] == "ok", result
    assert result["source_sha256"] == item["source_sha256"]
    return result["data"]


def test_browser_post_server_bytes_saved_record_and_reader_through_sdk(network_site, tmp_path):
    from l4_orchestrator.sdk_files import FileConnections
    site, received = network_site

    async def check(page):
        capture, tool, reader, store = connected(page, tmp_path)
        try:
            await page.goto(site)
            assert await fetch(page, "/api", body='{"value":"direct-before-flow"}') == 200
            await ready(capture)
            first_server = received.get(timeout=2)
            assert first_server["body"] == b'{"value":"direct-before-flow"}'
            assert any(item["resource_type"] == "document" for item in (await rows(tool))["requests"])
            state = capture.state
            registry = ElementRegistry(state, timeout_ms=3000)
            queries = make_query_tool(registry.state, elements=registry)
            await page.locator("input").fill("flow-fixture")
            found = (await queries.execute(query()))["result"]
            button = next(item for item in found["elements"] if item["role"] == "button")

            async def inspect_network(previous):
                await page.wait_for_function("window.finished === true")
                await ready(capture)
                return action()

            def inspect_body(previous):
                candidates = previous[-1]["result"]["requests"]
                item = next(item for item in reversed(candidates) if item["url"].endswith("/api"))
                return {"record_ref": item["record_ref"], "pointer": "/request/body/data"}

            proof = await run_native_steps({
                "click": ClickTool(registry, timeout_ms=3000, page_events=capture.page_events),
                "get_network_requests": tool, "record_reader": reader}, [
                ("click", click_action(button["element_id"], found["state_id"])),
                ("get_network_requests", inspect_network), ("record_reader", inspect_body)],
                files=FileConnections(producers=(store,), close_callbacks=(capture.close,)))
            captured_server = received.get(timeout=2)
            assert proof.results[2]["data"].encode() == captured_server["body"] == b'{"value":"flow-fixture"}'
            saved = proof.results[1]
            assert "flow-fixture" not in json.dumps(saved)
            assert saved["before_state_id"] is None and saved["after_state_id"] is None
            item = next(item for item in reversed(saved["result"]["requests"]) if item["url"].endswith("/api"))
            record = detail(reader, item)
            assert record["response"]["body"]["data"].encode() == API_BODY
            cookies = [h["value"] for h in record["response"]["headers"]["data"] if h["name"].lower() == "set-cookie"]
            assert len(cookies) == 2 and any("first=1" in value for value in cookies) and any("second=2" in value for value in cookies)
        finally:
            await capture.close()
    asyncio.run(with_page(site, check))


def test_pending_completed_and_later_saved_reference_have_new_sequences(network_site, tmp_path):
    site, received = network_site

    async def check(page):
        await page.goto(site)
        saving, release = asyncio.Event(), asyncio.Event()
        reader = RecordReader({}, max_data_bytes=65536)
        store = LocalNetworkStore(tmp_path, reader, max_record_bytes=131072)

        async def delayed_save(record):
            saving.set()
            await release.wait()
            return await store.save(record)

        capture, tool, unused_reader, unused_store = connected(page, tmp_path, save=delayed_save)
        try:
            async with page.expect_request("**/slow"):
                await page.evaluate("() => {window.slow=fetch('/slow').then(r=>r.text());}")
            first = await rows(tool)
            item = next(item for item in first["requests"] if item["url"].endswith("/slow"))
            assert item["network_state"] == "pending" and item["record_ref"] is None
            await saving.wait()
            second = await rows(tool, after=first["next_after_sequence"], capture_id=first["capture_id"])
            later = next(value for value in second["requests"] if value["request_id"] == item["request_id"])
            assert later["network_state"] == "completed" and later["detail_state"] == "pending" and later["record_ref"] is None
            assert later["sequence"] > item["sequence"]
            release.set()
            await ready(capture)
            third = await rows(tool, after=second["next_after_sequence"], capture_id=first["capture_id"])
            saved = next(value for value in third["requests"] if value["request_id"] == item["request_id"])
            assert saved["detail_state"] == "saved" and saved["sequence"] > later["sequence"]
            assert detail(reader, saved)["network_state"] == "completed"
        finally:
            release.set()
            await capture.close()
    asyncio.run(with_page(site, check))


def test_pagination_and_repeated_url_and_redirects_keep_request_identity(network_site, tmp_path):
    site, received = network_site

    async def check(page):
        await page.goto(site)
        capture, tool, reader, store = connected(page, tmp_path)
        try:
            await fetch(page, "/api")
            await fetch(page, "/api")
            await page.goto(site + "/redirect")
            await ready(capture)
            collected, cursor = [], 0
            while True:
                result = await rows(tool, after=cursor, capture_id=capture.capture_id, limit=1)
                collected.extend(result["requests"])
                if not result["has_more"]:
                    break
                assert result["next_after_sequence"] == result["requests"][-1]["sequence"]
                cursor = result["next_after_sequence"]
            same = [item for item in collected if item["url"].endswith("/api")]
            assert len(same) == 2 and same[0]["request_id"] != same[1]["request_id"]
            redirect = next(item for item in collected if item["url"].endswith("/redirect"))
            destination = next(item for item in collected if item["url"].endswith("/destination"))
            assert redirect["response_status"] == 302 and destination["redirected_from_request_id"] == redirect["request_id"]
            assert destination["network_state"] == "completed" and detail(reader, destination)["response"]["status"] == 200
        finally:
            await capture.close()
    asyncio.run(with_page(site, check))


def test_http_error_network_failure_and_empty_body_are_distinct(network_site, tmp_path):
    site, received = network_site

    async def check(page):
        await page.goto(site)
        capture, tool, reader, store = connected(page, tmp_path)
        try:
            assert await fetch(page, "/missing") == 404
            await fetch(page, "/empty")
            await page.route(site + "/blocked", lambda route: route.abort())
            await page.evaluate("() => fetch('/blocked').catch(()=>{})")
            await ready(capture)
            records = {item["url"].rsplit("/", 1)[-1]: (item, detail(reader, item)) for item in (await rows(tool))["requests"]}
            missing, raw_missing = records["missing"]
            assert missing["network_state"] == "completed" and missing["response_status"] == 404 and missing["failure"] is None
            empty, raw_empty = records["empty"]
            assert raw_empty["response"]["body"]["status"] == "captured"
            assert raw_empty["response"]["body"]["data"] == "" and raw_empty["response"]["body"]["byte_length"] == 0
            blocked, raw_blocked = records["blocked"]
            assert blocked["network_state"] == "failed" and blocked["failure"] and raw_blocked["response"] is None
            assert blocked["response_body_status"] == "no_response"
        finally:
            await capture.close()
    asyncio.run(with_page(site, check))


def test_binary_bytes_and_unselected_response_are_preserved_or_explicit(network_site, tmp_path):
    site, received = network_site

    async def check(page):
        await page.goto(site)
        capture, tool, reader, store = connected(page, tmp_path)
        try:
            await fetch(page, "/binary")
            await ready(capture)
            raw = detail(reader, (await rows(tool))["requests"][0])["response"]["body"]
            assert raw["encoding"] == "base64" and base64.b64decode(raw["data"]) == BINARY
            assert raw["sha256"] == hashlib.sha256(BINARY).hexdigest()
        finally:
            await capture.close()
        other, other_tool, other_reader, other_store = connected(page, tmp_path, body_types=set())
        try:
            await fetch(page, "/api")
            await ready(other)
            raw = detail(other_reader, (await rows(other_tool))["requests"][0])
            assert raw["response"]["body"]["status"] == "not_selected" and raw["response"]["body"]["data"] is None
        finally:
            await other.close()
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("limit_kind", ["per_body", "total", "requests"])
def test_capture_limits_are_explicit_and_not_silent_empty_results(network_site, tmp_path, limit_kind):
    site, received = network_site

    async def check(page):
        await page.goto(site)
        kwargs = {"max_body_bytes": 8} if limit_kind == "per_body" else {"max_total_body_bytes": len(API_BODY)} if limit_kind == "total" else {"max_requests": 1}
        capture, tool, reader, store = connected(page, tmp_path, **kwargs)
        try:
            await fetch(page, "/large" if limit_kind == "per_body" else "/api")
            await ready(capture)
            await fetch(page, "/api")
            await ready(capture)
            result = await rows(tool)
            if limit_kind == "requests":
                assert len(result["requests"]) == 1 and result["dropped_requests"] >= 1 and result["request_limit_reached"]
            else:
                bodies = [detail(reader, item)["response"]["body"] for item in result["requests"]]
                assert any(body["status"] == ("body_limit" if limit_kind == "per_body" else "total_limit") for body in bodies)
                assert result["retained_body_bytes"] <= capture.max_total_body_bytes
        finally:
            await capture.close()
    asyncio.run(with_page(site, check))


@pytest.mark.parametrize("failure", ["save", "receipt", "record_limit", "headers", "body", "timeout"])
def test_detail_failures_do_not_fabricate_ready_refs_or_empty_bodies(network_site, tmp_path, monkeypatch, failure):
    site, received = network_site

    async def check(page):
        await page.goto(site)

        async def failed_save(record):
            raise OSError("Injected disk failure")

        async def bad_receipt(record):
            return SavedNetworkRecord("not-saved", "0" * 64)

        capture, tool, reader, store = connected(page, tmp_path, save=failed_save if failure == "save" else bad_receipt if failure == "receipt" else None, timeout_ms=80)
        if failure == "record_limit":
            store.max_record_bytes = 8
        original = Response.body

        async def failed_body(response):
            if response.url.endswith("/api"):
                if failure == "timeout":
                    await asyncio.Event().wait()
                raise Error("Injected unavailable response body")
            return await original(response)

        if failure in {"body", "timeout"}:
            monkeypatch.setattr(Response, "body", failed_body)
        if failure == "headers":
            async def fail_headers(request):
                raise Error("Injected unavailable request headers")
            monkeypatch.setattr(Request, "headers_array", fail_headers)
        try:
            await fetch(page, "/api")
            await ready(capture)
            item = next(item for item in (await rows(tool))["requests"] if item["url"].endswith("/api"))
            assert item["network_state"] == "completed"
            if failure in {"save", "receipt", "record_limit"}:
                assert item["detail_state"] == "failed" and item["record_ref"] is None and item["source_sha256"] is None
                assert item["detail_error"] == "DETAIL_SAVE_FAILED"
            elif failure == "headers":
                record = detail(reader, item)
                assert record["request"]["headers"] == {"status": "read_failed", "data": None}
                assert record["response"]["body"]["data"].encode() == API_BODY
            else:
                body = detail(reader, item)["response"]["body"]
                assert body["status"] == ("read_failed" if failure == "body" else "timeout") and body["data"] is None
        finally:
            await capture.close()
    asyncio.run(with_page(site, check))


def test_read_only_query_keeps_dom_state_and_retains_history_after_page_close(network_site, tmp_path):
    site, received = network_site

    async def check(page):
        await page.goto(site)
        capture, tool, reader, store = connected(page, tmp_path)
        await fetch(page, "/api")
        await ready(capture)
        before = await capture.state.refresh()
        body = await page.content()
        result = await tool.execute(action())
        assert capture.state.read() == before and await page.content() == body
        assert result["before_state_id"] is None and result["after_state_id"] is None
        await page.close()
        await capture.close()
        result = await rows(tool)
        assert not result["capture_active"] and result["requests"][0]["detail_state"] == "saved"
        assert detail(reader, result["requests"][0])["response"]["body"]["data"].encode() == API_BODY
    asyncio.run(with_page(site, check))


def test_stop_records_unfinished_and_does_not_close_page(network_site, tmp_path):
    site, received = network_site

    async def check(page):
        await page.goto(site)
        capture, tool, reader, store = connected(page, tmp_path)
        async with page.expect_request("**/hold"):
            await page.evaluate("() => {window.hold=fetch('/hold').catch(()=>{});}")
        assert not await capture.flush(timeout_ms=10)
        await capture.close()
        assert not page.is_closed() and not capture._tasks
        item = (await rows(tool))["requests"][0]
        assert item["network_state"] == "unfinished" and item["failure"] is None
        assert detail(reader, item)["network_state"] == "unfinished"
        previous = capture.snapshot(after_sequence=0, limit=40)["latest_sequence"]
        await fetch(page, "/api")
        assert capture.snapshot(after_sequence=0, limit=40)["latest_sequence"] == previous
    asyncio.run(with_page(site, check))


def test_query_cursors_limits_and_input_shape_are_checked(network_site, tmp_path):
    site, received = network_site

    async def check(page):
        await page.goto(site)
        capture, tool, reader, store = connected(page, tmp_path)
        try:
            first = await rows(tool)
            assert first["requests"] == [] and first["capture_started_at"]
            for arguments, code in [(action(limit=41), "RETURN_LIMIT_EXCEEDED"),
                                    (action(capture_id="another"), "CAPTURE_MISMATCH"),
                                    (action(after=100, capture_id=capture.capture_id), "INVALID_CURSOR")]:
                result = await tool.execute(arguments)
                assert result["error"]["code"] == code and result["result"] is None
            for arguments in [action(limit=True), action(after=-1), action(after=1), action(limit="10")]:
                with pytest.raises(ValidationError):
                    GetNetworkRequestsInput.model_validate(arguments)
            invalid = action()
            invalid["context"]["state_id"] = "old-dom"
            with pytest.raises(ValidationError):
                GetNetworkRequestsInput.model_validate(invalid)
        finally:
            await capture.close()
    asyncio.run(with_page(site, check))


def test_store_registers_same_reader_and_rejects_changes_and_oversize(tmp_path):
    reader = RecordReader({}, max_data_bytes=4096)
    store = LocalNetworkStore(tmp_path, reader, max_record_bytes=4096)
    saved = asyncio.run(store.save({"request": {"body": {"data": "original"}}}))
    assert reader.read({"record_ref": saved.record_ref, "pointer": "/request/body/data"})["data"] == "original"
    path = next(tmp_path.glob("*.json"))
    source = RecordSource(path, saved.sha256)
    reader.register(saved.record_ref, source)  # Exact same registration is harmless.
    with pytest.raises(ValueError):
        reader.register(saved.record_ref, RecordSource(path, "0" * 64))
    before = set(tmp_path.iterdir())
    with pytest.raises(ValueError):
        asyncio.run(store.save({"huge": "x" * 5000}))
    assert set(tmp_path.iterdir()) == before
    path.write_text('{"changed":true}', encoding="utf-8")
    assert reader.read({"record_ref": saved.record_ref, "pointer": ""})["error"]["code"] == "RECORD_CHANGED"
    with pytest.raises(ValueError):
        LocalNetworkStore("relative", reader, max_record_bytes=4096)


def test_reverse_completion_and_paged_updates_do_not_lose_later_detail(network_site, tmp_path):
    site, received = network_site

    async def check(page):
        await page.goto(site)
        entered, release = asyncio.Event(), asyncio.Event()

        async def hold(route):
            entered.set()
            await release.wait()
            await route.continue_()

        await page.route(site + "/gated", hold)
        capture, tool, reader, store = connected(page, tmp_path)
        try:
            await page.evaluate("() => {window.gated=fetch('/gated').then(r=>r.text());}")
            await entered.wait()
            first = await rows(tool, limit=1)
            slow = first["requests"][0]
            assert slow["network_state"] == "pending"
            await fetch(page, "/api")

            async def fast_saved():
                while True:
                    result = await rows(tool, after=first["next_after_sequence"], capture_id=capture.capture_id, limit=1)
                    if result["requests"] and result["requests"][0]["detail_state"] == "saved":
                        return result
                    await asyncio.sleep(0.01)

            second = await asyncio.wait_for(fast_saved(), 3)
            fast = second["requests"][0]
            assert fast["url"].endswith("/api") and fast["request_id"] != slow["request_id"]
            release.set()
            await page.evaluate("window.gated")
            await ready(capture)
            third = await rows(tool, after=second["next_after_sequence"], capture_id=capture.capture_id, limit=1)
            completed = third["requests"][0]
            assert completed["request_id"] == slow["request_id"] and completed["detail_state"] == "saved"
            assert detail(reader, completed)["network_state"] == "completed"
        finally:
            release.set()
            await capture.close()
    asyncio.run(with_page(site, check))


def test_actual_binary_post_bytes_and_request_payload_limit(network_site, tmp_path):
    site, received = network_site

    async def check(page):
        await page.goto(site)
        capture, tool, reader, store = connected(page, tmp_path, max_body_bytes=len(BINARY))
        try:
            await page.evaluate("async payload => {await fetch('/binary-post',{method:'POST',body:new Uint8Array(payload)});}", list(BINARY))
            await ready(capture)
            item = (await rows(tool))["requests"][0]
            body = detail(reader, item)["request"]["body"]
            assert body["encoding"] == "base64" and base64.b64decode(body["data"]) == BINARY
            native = received.get(timeout=2)
            assert native["path"] == "/binary-post" and native["body"] == BINARY
            await fetch(page, "/too-large-post", body="x" * 50)
            await ready(capture)
            item = next(item for item in (await rows(tool))["requests"] if item["url"].endswith("/too-large-post"))
            body = detail(reader, item)["request"]["body"]
            assert body["status"] == "body_limit" and body["byte_length"] == 50 and body["data"] is None
            assert received.get(timeout=2)["body"] == b"x" * 50
        finally:
            await capture.close()
    asyncio.run(with_page(site, check))


def test_cancel_capture_marks_unready_without_cancelling_page_request(network_site, tmp_path):
    site, received = network_site

    async def check(page):
        await page.goto(site)
        capture, tool, reader, store = connected(page, tmp_path)
        async with page.expect_request("**/hold"):
            await page.evaluate("() => {window.hold=fetch('/hold').then(r=>r.text());}")
        pending = next(iter(capture._tasks))
        await asyncio.sleep(0)  # The task enters the request-header read before cancellation.
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
        item = (await rows(tool))["requests"][0]
        assert item["detail_state"] == "cancelled" and item["record_ref"] is None
        assert not page.is_closed() and not list(tmp_path.glob("*.json"))
        await page.evaluate("window.hold")  # Capture cancellation did not abort the HTTP operation.
        await capture.close()
    asyncio.run(with_page(site, check))


def test_store_finishes_registration_when_cancelled_during_scheduled_write(tmp_path, monkeypatch):
    async def check():
        reader = RecordReader({}, max_data_bytes=4096)
        store = LocalNetworkStore(tmp_path, reader, max_record_bytes=4096)
        entered, release, original = asyncio.Event(), asyncio.Event(), asyncio.to_thread

        async def scheduled(function, *args, **kwargs):
            entered.set()
            await release.wait()
            return await original(function, *args, **kwargs)

        monkeypatch.setattr(asyncio, "to_thread", scheduled)
        pending = asyncio.create_task(store.save({"source": "completed bytes"}))
        await entered.wait()
        pending.cancel()
        await asyncio.sleep(0)
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await pending
        files = list(tmp_path.glob("*.json"))
        assert len(files) == 1
        result = reader.read({"record_ref": "network://records/" + files[0].stem, "pointer": "/source"})
        assert result["status"] == "ok" and result["data"] == "completed bytes"
    asyncio.run(check())


def test_store_finishes_registration_after_repeated_cancellation_in_disk_thread(tmp_path, monkeypatch):
    async def check():
        reader = RecordReader({}, max_data_bytes=4096)
        store = LocalNetworkStore(tmp_path, reader, max_record_bytes=4096)
        entered, release, original = ThreadEvent(), ThreadEvent(), asyncio.to_thread

        async def blocked_disk_write(function, *args, **kwargs):
            def in_thread():
                entered.set()
                if not release.wait(3):
                    raise TimeoutError("The test did not release the disk thread")
                return function(*args, **kwargs)
            return await original(in_thread)

        monkeypatch.setattr(asyncio, "to_thread", blocked_disk_write)
        pending = asyncio.create_task(store.save({"source": "completed thread bytes"}))
        try:
            async def wait_for_thread():
                while not entered.is_set():
                    await asyncio.sleep(0.01)
            await asyncio.wait_for(wait_for_thread(), 2)
            for _ in range(2):
                pending.cancel()
                await asyncio.sleep(0.02)
            assert not pending.done()  # Registration still belongs to the protected write task.
        finally:
            release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(pending, 3)
        files = list(tmp_path.glob("*.json"))
        assert len(files) == 1
        result = reader.read({"record_ref": "network://records/" + files[0].stem, "pointer": "/source"})
        assert result["status"] == "ok" and result["data"] == "completed thread bytes"
    asyncio.run(check())
