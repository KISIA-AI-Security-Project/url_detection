"""불변 페이지 스냅샷을 기존 L2 HTTP Raw Data로 변환한다."""

from __future__ import annotations

import hashlib
import base64
import os
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


class MimeDetectionError(RuntimeError):
    def __init__(self,code,error):
        self.code,self.error_type=code,type(error).__name__
        super().__init__(str(error))

def _detect_mime(body: bytes) -> str | None:
    """설치·초기화·분류 실패를 구분하고 접두부 MIME 추정값을 반환한다."""
    try:
        magic = import_module("magic")
    except ModuleNotFoundError as exc:
        raise MimeDetectionError('mime_dependency_missing',exc) from exc
    except Exception as exc:
        raise MimeDetectionError('mime_library_initialization_failed',exc) from exc
    try:
        if os.environ.get('L2_MAGIC_DATABASE'):
            return str(magic.Magic(mime=True,magic_file=os.environ['L2_MAGIC_DATABASE']).from_buffer(body[:MAGIC_PROBE_BYTES]))
        return str(magic.from_buffer(body[:MAGIC_PROBE_BYTES], mime=True))
    except Exception as exc:
        raise MimeDetectionError('mime_detection_failed',exc) from exc


def _l2_errors(snapshot: PageSnapshot) -> list[dict[str, Any]]:
    """공통 구조화 오류를 기존 L2 오류 계약으로 손실 없이 축약한다."""
    errors: list[dict[str, Any]] = []
    for error in snapshot.collection_errors:
        details = dict(error.details)
        errors.append(
            {
                "url": details.get("url", snapshot.current_url),
                "error": f"{error.code}: {error.message}",
                "stage": error.stage, "code":error.code, "details":dict(error.details),
                "impact_scope":"acquisition",
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
    errors = _l2_errors(snapshot)
    try: detected_type = _detect_mime(body) if body else None
    except MimeDetectionError as exc:
        detected_type=None
        errors.append({'stage':'body_type','code':exc.code,'error_type':exc.error_type,
                       'impact_scope':'analysis',
                       'url':snapshot.final_url or snapshot.current_url,'error':str(exc)})

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
        "snapshot_id":snapshot.snapshot_id,
        "http_policy_blocked":any(e.code == "target_policy_blocked" for e in snapshot.collection_errors),
        "current_url": snapshot.current_url,
        "response_received": snapshot.response_received,
        "redirect_journey_complete": snapshot.metadata()["redirect_journey_complete"],
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
            "type_classification":{"method":"libmagic prefix heuristic","probe_bytes":min(len(body),MAGIC_PROBE_BYTES),
                                   "file_execution_observed":False,"complete_file_format_validation":False},
            "sha256": body_sha256,
            "truncated": snapshot.truncated,
            "received_bytes":len(body),
            "body_complete":snapshot.response_received and not snapshot.truncated,
            "captured_sha256":snapshot.captured_body_sha256,
            "captured_bytes_base64":base64.b64encode(body).decode('ascii'),
            "capture_scope":"HTTP client decoded response bytes; bounded by collection policy; not executed",
        },
        "download": {
            "filename": filename,
            "extension": extension_from_filename(filename) if filename else None,
            "mime_type": split_mime(content_type),
            "magic_bytes": body[:MAGIC_SIGNATURE_BYTES].hex() if body else None,
        },
        "errors": errors,
    }
