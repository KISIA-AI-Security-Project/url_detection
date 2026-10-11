"""Observe bounded HTTP records on one Page; never send or alter a request."""
import asyncio
import base64
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from typing import Awaitable, Callable
from urllib.parse import urlsplit
from uuid import uuid4

from playwright.async_api import Error

from .network_storage import SavedNetworkRecord
from .page_events import PageEvents
from .page_state import PageState


_RESOURCE_TYPES = {"document", "stylesheet", "image", "media", "font", "script", "texttrack",
                   "xhr", "fetch", "eventsource", "websocket", "manifest", "other"}


def _now():
    return datetime.now(timezone.utc).isoformat()


def _missing(status, *, byte_length=None):
    return {"status": status, "encoding": None, "data": None,
            "byte_length": byte_length, "sha256": None}


@dataclass
class _Request:
    original: object
    summary: dict
    record: dict
    ended: asyncio.Event = field(default_factory=asyncio.Event)
    response: object = None


class NetworkCapture:
    """Attach before navigation; the caller owns lifetime, limits and body selection."""
    def __init__(self, state: PageState, *, page_events: PageEvents,
                 save_record: Callable[[dict], Awaitable[SavedNetworkRecord]],
                 max_requests: int, max_body_bytes: int, max_total_body_bytes: int,
                 capture_timeout_ms: int, response_body_types: set[str]):
        for value in (max_requests, max_body_bytes, max_total_body_bytes, capture_timeout_ms):
            if type(value) is not int or value < 1:
                raise ValueError("Capture limits must be positive integers")
        if page_events.state is not state or not callable(save_record):
            raise ValueError("Network capture needs the same PageEvents and a record saver")
        if not set(response_body_types) <= _RESOURCE_TYPES:
            raise ValueError("Unknown response resource type")
        state._check_page()
        self.state, self.page_events, self.save_record = state, page_events, save_record
        self.max_requests, self.max_body_bytes = max_requests, max_body_bytes
        self.max_total_body_bytes, self.capture_timeout_ms = max_total_body_bytes, capture_timeout_ms
        self.response_body_types = frozenset(response_body_types)
        self.capture_id, self.started_at = "capture_" + uuid4().hex, _now()
        self.stopped_at = None
        self._entries, self._tasks = {}, set()
        self._sequence, self._dropped, self._body_bytes = 0, 0, 0
        self._body_lock = asyncio.Lock()  # Only one full response body read at a time.
        self._listeners = {"request": self._request, "response": self._response,
                           "requestfinished": self._finished, "requestfailed": self._failed,
                           "close": self.stop, "crash": self.stop}
        for event, callback in self._listeners.items():
            state.page.on(event, callback)

    def _touch(self, entry):
        self._sequence += 1
        entry.summary["sequence"] = self._sequence
        entry.summary["updated_at"] = _now()

    def _request(self, request):
        if self.stopped_at is not None or urlsplit(request.url).scheme not in {"http", "https"}:
            return
        if len(self._entries) >= self.max_requests:
            self._dropped += 1
            self._sequence += 1
            return
        rid, observed_at = "net_" + uuid4().hex, _now()
        previous = request.redirected_from
        predecessor = self._entries.get(previous)
        action_id = self.page_events._action_id  # Observation interval, never a causal attribution.
        summary = {"request_id": rid, "url": request.url, "method": request.method,
                   "resource_type": request.resource_type, "observed_at": observed_at,
                   "observed_during_action_id": action_id, "network_state": "pending",
                   "response_status": None, "failure": None,
                   "redirected_from_request_id": predecessor.summary["request_id"] if predecessor else None,
                   "redirected_from_url": previous.url if previous else None,
                   "detail_state": "pending", "record_ref": None, "source_sha256": None,
                   "detail_error": None, "request_body_status": "pending", "response_body_status": "pending"}
        record = {"schema_version": "l4-network-1", "capture_id": self.capture_id,
                  "page_id": self.state.page_id, "request_id": rid, "observed_at": observed_at,
                  "observed_during_action_id": action_id, "finished_at": None, "network_state": "pending",
                  "redirected_from_request_id": summary["redirected_from_request_id"],
                  "redirected_from_url": summary["redirected_from_url"], "failure": None,
                  "request": {"url": request.url, "method": request.method, "resource_type": request.resource_type,
                              "headers": {"status": "pending", "data": None}, "body": _missing("pending")},
                  "response": None}
        # Copy the request payload immediately, before an asynchronous read/navigation can lose it.
        try:
            raw = request.post_data_buffer
            record["request"]["body"] = self._body(raw) if raw is not None else _missing("unavailable")
        except Error:
            record["request"]["body"] = _missing("read_failed")
        summary["request_body_status"] = record["request"]["body"]["status"]
        entry = _Request(request, summary, record)
        self._entries[request] = entry
        self._touch(entry)
        task = asyncio.create_task(self._complete(entry))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def _body(self, raw):
        length = len(raw)
        if length > self.max_body_bytes:
            return _missing("body_limit", byte_length=length)
        if self._body_bytes + length > self.max_total_body_bytes:
            return _missing("total_limit", byte_length=length)
        self._body_bytes += length
        try:
            data, encoding = raw.decode("utf-8"), "utf-8"
        except UnicodeDecodeError:
            data, encoding = base64.b64encode(raw).decode("ascii"), "base64"
        return {"status": "captured", "encoding": encoding, "data": data,
                "byte_length": length, "sha256": hashlib.sha256(raw).hexdigest()}

    def _response(self, response):
        entry = self._entries.get(response.request)
        if entry is not None and not entry.ended.is_set():
            entry.response = response
            entry.summary.update(network_state="response_received", response_status=response.status)
            entry.record["response"] = {"url": response.url, "status": response.status,
                                         "headers": {"status": "pending", "data": None}, "body": _missing("pending")}
            self._touch(entry)

    def _end(self, request, state):
        entry = self._entries.get(request)
        if entry is not None and not entry.ended.is_set():
            failure = request.failure if state == "failed" else None
            entry.record.update(network_state=state, finished_at=_now(), failure=failure)
            entry.summary.update(network_state=state, failure=failure)
            entry.ended.set()
            self._touch(entry)

    def _finished(self, request):
        self._end(request, "completed")  # HTTP 404/500 can still be completed responses.

    def _failed(self, request):
        self._end(request, "failed")

    async def _headers(self, value):
        try:
            data = await asyncio.wait_for(value.headers_array(), self.capture_timeout_ms / 1000)
            return {"status": "captured", "data": data}  # Preserve duplicate headers as an array.
        except TimeoutError:
            return {"status": "timeout", "data": None}
        except Error:
            return {"status": "read_failed", "data": None}

    async def _response_body(self, entry):
        if entry.summary["resource_type"] not in self.response_body_types:
            return _missing("not_selected")
        if entry.record["network_state"] != "completed":
            return _missing("unfinished")
        try:
            async with asyncio.timeout(self.capture_timeout_ms / 1000):
                async with self._body_lock:
                    if self._body_bytes >= self.max_total_body_bytes:
                        return _missing("total_limit")
                    headers = entry.record["response"]["headers"]["data"] or []
                    lengths = [h["value"] for h in headers if h["name"].lower() == "content-length"]
                    if len(lengths) == 1 and lengths[0].isdigit() and int(lengths[0]) > self.max_body_bytes:
                        return _missing("body_limit")  # Wire length is not the decoded body's exact length.
                    # Playwright reads a whole body. These limits bound retained bytes, not peak memory.
                    return self._body(await entry.response.body())
        except TimeoutError:
            return _missing("timeout")
        except Error:
            return _missing("read_failed")

    async def _complete(self, entry):
        stage = "capture"
        try:
            entry.record["request"]["headers"] = await self._headers(entry.original)
            await entry.ended.wait()
            if entry.response is not None:
                entry.record["response"]["headers"] = await self._headers(entry.response)
                entry.record["response"]["body"] = await self._response_body(entry)
                entry.summary["response_body_status"] = entry.record["response"]["body"]["status"]
            else:
                entry.summary["response_body_status"] = "no_response"
            record = deepcopy(entry.record)
            digest = hashlib.sha256(json.dumps(record, ensure_ascii=False, allow_nan=False,
                                                separators=(",", ":")).encode("utf-8")).hexdigest()
            stage = "save"
            saved = await self.save_record(record)
            if not isinstance(saved, SavedNetworkRecord) or not saved.record_ref or saved.sha256 != digest:
                raise ValueError("The saver did not return a registered record receipt")
            entry.summary.update(detail_state="saved", record_ref=saved.record_ref, source_sha256=saved.sha256)
        except asyncio.CancelledError:
            entry.summary.update(detail_state="cancelled", detail_error="CAPTURE_CANCELLED")
            raise
        except Exception:
            entry.summary.update(detail_state="failed", detail_error="DETAIL_SAVE_FAILED" if stage == "save" else "DETAIL_CAPTURE_FAILED")
        finally:
            self._touch(entry)  # A later saved reference must be visible to incremental readers.

    def snapshot(self, *, after_sequence: int, limit: int, capture_id=None):
        if capture_id is not None and capture_id != self.capture_id:
            raise ValueError("CAPTURE_MISMATCH")
        if after_sequence > self._sequence:
            raise ValueError("INVALID_CURSOR")
        items = sorted((entry.summary for entry in self._entries.values()
                        if entry.summary["sequence"] > after_sequence), key=lambda item: item["sequence"])
        selected = items[:limit]
        return {"capture_id": self.capture_id, "page_id": self.state.page_id,
                "capture_started_at": self.started_at, "capture_stopped_at": self.stopped_at,
                "capture_active": self.stopped_at is None,
                "scope": "assigned_page_http_events", "requests": deepcopy(selected),
                "next_after_sequence": selected[-1]["sequence"] if selected else self._sequence,
                "has_more": len(items) > len(selected), "latest_sequence": self._sequence,
                "dropped_requests": self._dropped, "request_limit_reached": len(self._entries) >= self.max_requests,
                "retained_body_bytes": self._body_bytes}

    async def flush(self, *, timeout_ms: int):
        """Wait at most this long for known records; never wait for new traffic."""
        if type(timeout_ms) is not int or timeout_ms < 1:
            raise ValueError("timeout_ms must be positive")
        pending = set(self._tasks)
        if pending:
            _, pending = await asyncio.wait(pending, timeout=timeout_ms / 1000)
        return not pending

    def stop(self, *args):
        if self.stopped_at is None:
            self.stopped_at = _now()
            for event, callback in self._listeners.items():
                self.state.page.remove_listener(event, callback)
            for entry in self._entries.values():
                self._end(entry.original, "unfinished")

    async def close(self):
        """Detach and finish the bounded set of records. Does not close the Page."""
        self.stop()
        pending = list(self._tasks)
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
