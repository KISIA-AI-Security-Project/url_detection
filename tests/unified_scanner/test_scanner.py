from __future__ import annotations

from typing import Any

from url_collector.models import PageSnapshot
from url_collector.policy import CollectionPolicy

from unified_scanner.config import UnifiedConfig
from unified_scanner.scanner import UnifiedScanner


def snapshot() -> PageSnapshot:
    return PageSnapshot(
        snapshot_id="shared-snapshot",
        collected_at="2026-09-03T00:00:00+09:00",
        original_url="https://example.com/start",
        current_url="https://example.com/final",
        final_url="https://example.com/final",
        status_code=200,
        response_headers=(("content-type", "text/html"),),
        body=b"<html>same response</html>",
        captured_body_sha256="same-body-hash",
        content_type="text/html",
        encoding="utf-8",
        truncated=False,
        redirect_chain=(),
        collection_errors=(),
        request_profile=CollectionPolicy(10.0, 15, 5_000_000, "test"),
    )


class RecordingL3:
    def __init__(self) -> None:
        self.received: list[PageSnapshot] = []

    def scan_snapshot(self, value: PageSnapshot) -> dict[str, Any]:
        self.received.append(value)
        return {"layer": "L3", "snapshot_id": value.snapshot_id}


def test_collects_once_and_passes_identical_snapshot_object_to_both_layers() -> None:
    shared = snapshot()
    collection_calls: list[str] = []
    l2_received: list[PageSnapshot] = []
    l3 = RecordingL3()

    def collect(url: str, policy: CollectionPolicy) -> PageSnapshot:
        del policy
        collection_calls.append(url)
        return shared

    def run_l2(value: PageSnapshot) -> dict[str, Any]:
        l2_received.append(value)
        return {"layer": "L2", "snapshot_id": value.snapshot_id}

    result = UnifiedScanner(
        UnifiedConfig(collection=shared.request_profile),
        collector=collect,
        l2_runner=run_l2,
        l3_runner=l3,
    ).scan_url(shared.original_url)

    assert collection_calls == [shared.original_url]
    assert l2_received[0] is shared
    assert l3.received[0] is shared
    assert result["layers"]["l2"]["snapshot_id"] == "shared-snapshot"
    assert result["layers"]["l3"]["snapshot_id"] == "shared-snapshot"
    assert result["collection"]["captured_body_sha256"] == "same-body-hash"
    assert "body" not in result["collection"]


def test_layer_failure_does_not_prevent_other_layer_analysis() -> None:
    shared = snapshot()
    l3 = RecordingL3()

    def fail_l2(value: PageSnapshot) -> dict[str, Any]:
        del value
        raise RuntimeError("L2 failed")

    result = UnifiedScanner(
        UnifiedConfig(collection=shared.request_profile),
        collector=lambda url, policy: shared,
        l2_runner=fail_l2,
        l3_runner=l3,
    ).scan_url(shared.original_url)

    assert result["layers"]["l2"] is None
    assert result["layers"]["l3"]["layer"] == "L3"
    assert result["errors"] == [
        {"layer": "L2", "error_type": "RuntimeError", "message": "L2 failed"}
    ]
