"""명시적으로 허용된 외부 JavaScript Source를 제한 수집한다."""

from __future__ import annotations

import httpx

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
        script.collection_errors.append(
            collection_error(
                "script_collection",
                "script_collection_failed",
                str(exc),
                url=script.source_url,
            )
        )
        return script

    if response.content_type not in _JAVASCRIPT_CONTENT_TYPES:
        script.collection_errors.append(
            collection_error(
                "script_collection",
                "unsupported_script_content_type",
                "response is not a JavaScript content type",
                content_type=response.content_type,
            )
        )
        return script

    encoding = response.encoding or "utf-8"
    source = response.body.decode(encoding, errors="replace")
    script.source_url = response.url
    script.source = source
    script.sha256 = sha256_text(source)
    script.size = len(response.body)
    script.truncated = response.truncated
    script.collection_errors.extend(response.errors)
    return script
