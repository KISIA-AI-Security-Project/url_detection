"""공통 PageSnapshot에서 기존 L2 HTTP Raw 계약을 만드는 어댑터 테스트."""

from __future__ import annotations

from typing import Any

from url_collector.errors import CollectionError
from url_collector.models import PageSnapshot, RedirectHop
from url_collector.policy import CollectionPolicy

import l2_scanner.adapters.page_snapshot as adapter


def snapshot(**overrides: object) -> PageSnapshot:
    values: dict[str, object] = {
        "snapshot_id": "snapshot-1",
        "collected_at": "2026-09-03T00:00:00+09:00",
        "original_url": "https://example.com/start",
        "current_url": "https://example.com/payload.exe",
        "final_url": "https://example.com/payload.exe",
        "status_code": 200,
        "response_headers": (
            ("content-type", "application/octet-stream"),
            ("content-disposition", 'attachment; filename="payload.exe"'),
        ),
        "body": b"MZpayload",
        "captured_body_sha256": "captured",
        "content_type": "application/octet-stream",
        "encoding": None,
        "truncated": False,
        "redirect_chain": (
            RedirectHop(
                "https://example.com/start",
                "https://example.com/payload.exe",
                302,
                "/payload.exe",
            ),
        ),
        "collection_errors": (),
        "request_profile": CollectionPolicy(10.0, 15, 5_000_000, "test"),
    }
    values.update(overrides)
    return PageSnapshot(**values)  # type: ignore[arg-type]


def test_adapter_preserves_redirect_headers_body_and_download_metadata(
    monkeypatch: Any,
) -> None:
    monkeypatch.setattr(adapter, "_detect_mime", lambda body: "application/x-dosexec")

    raw = adapter.to_l2_http_raw(snapshot())

    assert raw["redirect_chain"][0]["destination_url"].endswith("payload.exe")
    assert raw["headers"]["content_disposition"].startswith("attachment")
    assert raw["response_body"]["detected_type"] == "application/x-dosexec"
    assert raw["response_body"]["sha256"] is not None
    assert raw["download"]["filename"] == "payload.exe"
    assert raw["download"]["extension"] == "exe"


def test_truncated_body_does_not_claim_full_hash() -> None:
    raw = adapter.to_l2_http_raw(
        snapshot(
            truncated=True,
            response_headers=(("content-length", "9000"),),
        )
    )

    assert raw["response_body"]["size"] == 9000
    assert raw["response_body"]["sha256"] is None


def test_collection_failure_remains_unknown_input() -> None:
    raw = adapter.to_l2_http_raw(
        snapshot(
            current_url="http://127.0.0.1/",
            final_url=None,
            status_code=None,
            response_headers=(),
            body=b"",
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

    assert raw["final_url"] is None
    assert raw["status_code"] is None
    assert raw["errors"][0]["url"] == "http://127.0.0.1/"
