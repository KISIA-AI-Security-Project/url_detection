"""불변 페이지 스냅샷을 기존 L2 HTTP Raw Data로 변환한다."""

from __future__ import annotations

import hashlib
from importlib import import_module
from typing import Any

from url_collector import PageSnapshot

from l2_scanner.config.tuning import MAGIC_PROBE_BYTES, MAGIC_SIGNATURE_BYTES
from l2_scanner.utils.http_parsing import (
    extension_from_filename,
    filename_from_url,
    parse_content_disposition,
    split_mime,
)


def _detect_mime(body: bytes) -> str | None:
    """설치된 libmagic binding으로 캡처 본문의 실제 MIME type을 확인한다."""
    try:
        magic = import_module("magic")
    except ModuleNotFoundError:
        return None
    return str(magic.from_buffer(body[:MAGIC_PROBE_BYTES], mime=True))


def _l2_errors(snapshot: PageSnapshot) -> list[dict[str, Any]]:
    """공통 구조화 오류를 기존 L2 오류 계약으로 손실 없이 축약한다."""
    errors: list[dict[str, Any]] = []
    for error in snapshot.collection_errors:
        details = dict(error.details)
        errors.append(
            {
                "url": details.get("url", snapshot.current_url),
                "error": f"{error.code}: {error.message}",
            }
        )
    return errors


def to_l2_http_raw(snapshot: PageSnapshot) -> dict[str, Any]:
    """네트워크 접근 없이 L2 Analyzer가 소비하는 기존 Raw 모양을 만든다."""
    content_type = (
        snapshot.header("content-type") if snapshot.response_received else None
    )
    content_disposition = (
        snapshot.header("content-disposition") if snapshot.response_received else None
    )
    refresh = snapshot.header("refresh") if snapshot.response_received else None
    body = snapshot.body
    detected_type = _detect_mime(body) if body else None
    errors = _l2_errors(snapshot)
    if body and detected_type is None:
        errors.append(
            {
                "url": snapshot.final_url or snapshot.current_url,
                "error": "mime_detection_unavailable: python-magic is not installed",
            }
        )

    declared_length = snapshot.header("content-length")
    if not body:
        body_size: int | None = None
        body_sha256: str | None = None
    elif snapshot.truncated:
        body_size = (
            int(declared_length)
            if declared_length is not None and declared_length.isdigit()
            else None
        )
        body_sha256 = None
    else:
        body_size = len(body)
        body_sha256 = hashlib.sha256(body).hexdigest()

    filename: str | None = None
    if content_disposition:
        filename = parse_content_disposition(content_disposition)["filename"]
    if filename is None and snapshot.final_url:
        filename = filename_from_url(snapshot.final_url)

    return {
        "original_url": snapshot.original_url,
        "current_url": snapshot.current_url,
        "final_url": snapshot.final_url,
        "status_code": snapshot.status_code,
        "redirect_chain": [hop.to_dict() for hop in snapshot.redirect_chain],
        "headers": {
            "content_type": content_type,
            "content_disposition": content_disposition,
            "refresh": refresh,
        },
        "response_body": {
            "size": body_size,
            "detected_type": detected_type,
            "sha256": body_sha256,
            "truncated": snapshot.truncated,
        },
        "download": {
            "filename": filename,
            "extension": extension_from_filename(filename) if filename else None,
            "mime_type": split_mime(content_type),
            "magic_bytes": body[:MAGIC_SIGNATURE_BYTES].hex() if body else None,
        },
        "errors": errors,
    }
