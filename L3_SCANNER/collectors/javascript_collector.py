"""명시적으로 허용된 외부 JavaScript Source를 제한 수집한다."""

from __future__ import annotations

import httpx
import base64
from hashlib import sha256
from L3_SCANNER.utils.decoding import decode_html

from L3_SCANNER.models.input import ScriptInput
from L3_SCANNER.policies.runtime import RuntimeConfig
from L3_SCANNER.utils.hashing import sha256_text
from .http_client import (
    Resolver,
    bounded_get,
    collection_error,
    system_resolver,
)

_JAVASCRIPT_CONTENT_TYPES = {
    "application/ecmascript",
    "application/javascript",
    "text/ecmascript",
    "text/javascript",
}


def collect_external_script(
    script: ScriptInput,
    runtime: RuntimeConfig,
    *,
    resolver: Resolver = system_resolver,
    transport: httpx.BaseTransport | None = None,
) -> ScriptInput:
    """외부 스크립트 하나를 페이지와 동일한 SSRF 제한으로 수집한다.

    JavaScript MIME type이 아니면 Source를 분석 대상으로 저장하지 않는다. 실제
    수집은 오케스트레이터가 개수 제한을 확인한 후 호출하며 기본 설정에서는 꺼져 있다.
    """
    if script.type != "external" or not script.source_url:
        return script
    if not runtime.fetch_external_scripts:
        return script
    try:
        response = bounded_get(
            script.source_url,
            max_bytes=runtime.max_script_bytes,
            runtime=runtime,
            resolver=resolver,
            transport=transport,
        )
    except (httpx.HTTPError, ValueError, OSError) as exc:
        code = (
            "script_request_timeout"
            if isinstance(exc, httpx.TimeoutException)
            else "script_dns_resolution_failed"
            if "DNS resolution" in str(exc)
            else "script_target_policy_blocked"
            if "non-public address" in str(exc)
            or "user information is not allowed" in str(exc)
            else "script_invalid_target"
            if isinstance(exc, ValueError)
            else "script_connection_failed"
        )
        script.collection_errors.append(
            collection_error(
                "script_collection",
                code,
                str(exc),
                url=script.source_url,
                error_type=type(exc).__name__,
            )
        )
        return script

    script.response = {
        "url": response.url,
        "status_code": response.status_code,
        "headers": response.headers,
        "received_bytes": len(response.body),
        "captured_sha256": sha256(response.body).hexdigest(),
        "body_complete": not response.truncated,
    }
    script.collection_errors.extend(response.errors)
    if response.status_code >= 400:
        script.response["captured_bytes_base64"] = base64.b64encode(
            response.body
        ).decode("ascii")
        return script
    if response.content_type not in _JAVASCRIPT_CONTENT_TYPES:
        script.response["captured_bytes_base64"] = base64.b64encode(
            response.body
        ).decode("ascii")
        script.collection_errors.append(
            collection_error(
                "script_collection",
                "unsupported_script_content_type",
                "response is not a JavaScript content type",
                content_type=response.content_type,
            )
        )
        return script

    source, encoding, encoding_source, errors = decode_html(
        response.body, response.encoding, allow_html_meta=False
    )
    script.response.update(encoding=encoding, encoding_source=encoding_source)
    if errors:
        script.response["captured_bytes_base64"] = base64.b64encode(
            response.body
        ).decode("ascii")
        script.collection_errors.extend(
            {"stage": "script_decoding", **error} for error in errors
        )
    script.source_url = response.url
    script.source = source
    script.sha256 = sha256_text(source)
    script.size = len(response.body)
    script.truncated = response.truncated
    return script
