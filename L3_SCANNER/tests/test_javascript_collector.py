"""공통 HTTP 스냅샷을 외부 JavaScript 입력으로 변환하는 테스트."""

from __future__ import annotations

from url_collector.models import PageSnapshot
from url_collector.policy import CollectionPolicy

from L3_SCANNER.adapters.script_snapshot import (
    apply_script_snapshot,
    script_collection_policy,
)
from L3_SCANNER.models.input import ScriptInput
from L3_SCANNER.policies.runtime import RuntimeConfig


def snapshot(**overrides: object) -> PageSnapshot:
    values: dict[str, object] = {
        "snapshot_id": "script-snapshot-1",
        "collected_at": "2026-09-03T00:00:00+09:00",
        "original_url": "https://cdn.example/a.js",
        "current_url": "https://cdn.example/a.js",
        "final_url": "https://cdn.example/a.js",
        "status_code": 200,
        "response_headers": (("content-type", "application/javascript"),),
        "body": b"1234",
        "captured_body_sha256": "captured",
        "content_type": "application/javascript",
        "encoding": "utf-8",
        "truncated": True,
        "redirect_chain": (),
        "collection_errors": (),
        "request_profile": CollectionPolicy(10.0, 5, 4, "test"),
    }
    values.update(overrides)
    return PageSnapshot(**values)  # type: ignore[arg-type]


def test_script_adapter_preserves_source_hash_size_and_truncation() -> None:
    script = apply_script_snapshot(
        ScriptInput("script-1", "external", source_url="https://cdn.example/a.js"),
        snapshot(),
    )

    assert script.source == "1234"
    assert script.size == 4
    assert script.truncated is True
    assert script.sha256 is not None


def test_script_adapter_rejects_non_javascript_content() -> None:
    script = apply_script_snapshot(
        ScriptInput("script-1", "external", source_url="https://cdn.example/a.js"),
        snapshot(content_type="text/html"),
    )

    assert script.source is None
    assert script.collection_errors[-1]["code"] == "unsupported_script_content_type"


def test_script_runtime_is_mapped_to_explicit_collection_policy() -> None:
    runtime = RuntimeConfig(
        request_timeout_seconds=3.0,
        max_redirects=2,
        max_script_bytes=321,
    )

    policy = script_collection_policy(runtime)

    assert policy.request_timeout_seconds == 3.0
    assert policy.max_redirects == 2
    assert policy.max_body_bytes == 321
