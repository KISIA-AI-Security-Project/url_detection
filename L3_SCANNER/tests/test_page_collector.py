"""공통 페이지 스냅샷에서 L3Input을 만드는 어댑터 테스트."""

from __future__ import annotations

from url_collector.errors import CollectionError
from url_collector.models import PageSnapshot
from url_collector.policy import CollectionPolicy

from L3_SCANNER.adapters.page_snapshot import page_collection_policy, to_l3_input
from L3_SCANNER.policies.runtime import RuntimeConfig


def snapshot(**overrides: object) -> PageSnapshot:
    values: dict[str, object] = {
        "snapshot_id": "snapshot-1",
        "collected_at": "2026-09-03T00:00:00+09:00",
        "original_url": "https://example.com/start",
        "current_url": "https://example.com/final",
        "final_url": "https://example.com/final",
        "status_code": 200,
        "response_headers": (("content-type", "text/html; charset=utf-8"),),
        "body": b"<html>ok</html>",
        "captured_body_sha256": "captured",
        "content_type": "text/html",
        "encoding": "utf-8",
        "truncated": False,
        "redirect_chain": (),
        "collection_errors": (),
        "request_profile": CollectionPolicy(10.0, 5, 2_000_000, "test"),
    }
    values.update(overrides)
    return PageSnapshot(**values)  # type: ignore[arg-type]


def test_adapter_preserves_final_url_html_and_collection_metadata() -> None:
    result = to_l3_input(snapshot(truncated=True))

    assert result.original_url == "https://example.com/start"
    assert result.document_url == "https://example.com/final"
    assert result.html.content == "<html>ok</html>"
    assert result.html.content_type == "text/html"
    assert result.html.truncated is True
    assert result.collection_errors == []


def test_adapter_preserves_collection_failure_as_missing_content() -> None:
    result = to_l3_input(
        snapshot(
            current_url="http://127.0.0.1/",
            final_url=None,
            status_code=None,
            response_headers=(),
            body=b"",
            content_type=None,
            encoding=None,
            collection_errors=(
                CollectionError.create(
                    "collection",
                    "request_failed",
                    "target resolves to a non-public address",
                    url="http://127.0.0.1/",
                ),
            ),
        )
    )

    assert result.html.content is None
    assert result.collection_errors[0]["code"] == "request_failed"


def test_non_html_response_is_preserved_but_marked_unsupported() -> None:
    result = to_l3_input(
        snapshot(
            response_headers=(("content-type", "application/json"),),
            body=b"{}",
            content_type="application/json",
        )
    )

    assert result.html.content == "{}"
    assert result.collection_errors[-1]["code"] == "unsupported_content_type"


def test_l3_runtime_is_mapped_to_explicit_collection_policy() -> None:
    runtime = RuntimeConfig(
        request_timeout_seconds=3.0,
        max_redirects=4,
        max_html_bytes=1234,
    )

    policy = page_collection_policy(runtime)

    assert policy.request_timeout_seconds == 3.0
    assert policy.max_redirects == 4
    assert policy.max_body_bytes == 1234
