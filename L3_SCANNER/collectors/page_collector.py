"""SSRF 사전 검증을 포함한 제한형 HTTP(S) 페이지 수집기.

모든 리다이렉트 목적지를 요청 전에 다시 검증하고, 환경 프록시를 사용하지 않으며,
응답을 스트리밍해 설정된 크기 이상 읽지 않는다. 이 수집기는 Raw 입력을 만들 뿐
페이지의 위험 여부를 판정하지 않는다.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from ..models.input import HTMLInput, L3Input, ScriptInput
from ..policies.runtime import RuntimeConfig
from ..utils.hashing import sha256_text
from ..utils.url import is_http_url

Resolver = Callable[[str, int], Iterable[str]]
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_HTML_CONTENT_TYPES = {"text/html", "application/xhtml+xml"}
_JAVASCRIPT_CONTENT_TYPES = {
    "application/ecmascript",
    "application/javascript",
    "text/ecmascript",
    "text/javascript",
}


def _error(stage: str, code: str, message: str, **details: Any) -> dict[str, Any]:
    """수집 단계 오류를 공통 직렬화 구조로 만든다."""
    return {"stage": stage, "code": code, "message": message, "details": details}


def _system_resolver(hostname: str, port: int) -> Iterable[str]:
    """호스트의 모든 TCP 주소를 반환해 우회 가능한 비공개 주소도 검사하게 한다."""
    records = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    return {str(record[4][0]) for record in records}


def _is_public_address(value: str) -> bool:
    """SSRF 대상이 될 수 있는 사설·로컬·예약 IP를 제외한다."""
    address = ipaddress.ip_address(value)
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def _validate_public_http_url(url: str, resolver: Resolver) -> None:
    """요청 직전 URL 형식과 DNS 결과 전체가 공개 주소인지 검증한다.

    Userinfo를 금지해 호스트 오인 가능성을 줄이고, 여러 DNS 결과 중 하나라도
    비공개 주소이면 요청 전체를 거부한다. 리다이렉트마다 이 함수를 다시 호출한다.
    """
    if not is_http_url(url):
        raise ValueError("only absolute HTTP(S) URLs are allowed")
    parts = urlsplit(url)
    if parts.username is not None or parts.password is not None:
        raise ValueError("URL user information is not allowed")
    try:
        port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
    except ValueError as exc:
        raise ValueError("URL port is malformed") from exc
    assert parts.hostname is not None
    try:
        addresses = tuple(resolver(parts.hostname, port))
    except OSError as exc:
        raise ValueError(f"DNS resolution failed: {exc}") from exc
    if not addresses:
        raise ValueError("DNS resolution returned no addresses")
    if any(not _is_public_address(address) for address in addresses):
        raise ValueError("target resolves to a non-public address")


@dataclass(slots=True)
class _CollectedResponse:
    """제한 수집 결과와 부분 실패 정보를 내부에서 전달하는 값 객체."""

    url: str
    body: bytes
    content_type: str | None
    encoding: str | None
    truncated: bool
    status_code: int
    errors: list[dict[str, Any]]


def _bounded_get(
    url: str,
    *,
    max_bytes: int,
    runtime: RuntimeConfig,
    resolver: Resolver,
    transport: httpx.BaseTransport | None,
) -> _CollectedResponse:
    """리다이렉트·시간·본문 크기를 제한하며 응답 하나를 수집한다.

    ``httpx``의 자동 리다이렉트를 끄고 각 Location을 다시 SSRF 검증한다. 본문은
    ``max_bytes``까지만 보존하며 초과 여부를 ``truncated``로 명시한다.
    """
    current_url = url
    errors: list[dict[str, Any]] = []

    with httpx.Client(
        follow_redirects=False,
        timeout=runtime.request_timeout_seconds,
        transport=transport,
        trust_env=False,
        headers={"User-Agent": "L3-Scanner/1.0"},
    ) as client:
        for redirect_count in range(runtime.max_redirects + 1):
            _validate_public_http_url(current_url, resolver)
            with client.stream("GET", current_url) as response:
                if response.status_code in _REDIRECT_STATUSES:
                    location = response.headers.get("location")
                    if not location:
                        errors.append(
                            _error(
                                "collection",
                                "redirect_without_location",
                                "redirect response has no Location",
                            )
                        )
                        return _CollectedResponse(
                            current_url,
                            b"",
                            None,
                            None,
                            False,
                            response.status_code,
                            errors,
                        )
                    if redirect_count >= runtime.max_redirects:
                        raise ValueError("redirect limit exceeded")
                    current_url = urljoin(current_url, location)
                    continue

                chunks: list[bytes] = []
                size = 0
                truncated = False
                # Content-Length는 누락되거나 거짓일 수 있으므로 실제 스트림을 읽는
                # 동안 남은 바이트를 계산해 메모리 사용량을 직접 제한한다.
                for chunk in response.iter_bytes():
                    remaining = max_bytes - size
                    if remaining <= 0:
                        truncated = True
                        break
                    chunks.append(chunk[:remaining])
                    size += min(len(chunk), remaining)
                    if len(chunk) > remaining:
                        truncated = True
                        break

                raw_content_type = response.headers.get("content-type")
                content_type = (
                    raw_content_type.split(";", 1)[0].strip().lower()
                    if raw_content_type
                    else None
                )
                if response.status_code >= 400:
                    errors.append(
                        _error(
                            "collection",
                            "http_error_status",
                            "server returned an HTTP error status",
                            status_code=response.status_code,
                        )
                    )
                return _CollectedResponse(
                    url=str(response.url),
                    body=b"".join(chunks),
                    content_type=content_type,
                    encoding=response.encoding,
                    truncated=truncated,
                    status_code=response.status_code,
                    errors=errors,
                )

    raise RuntimeError("bounded request loop ended unexpectedly")


def collect_page(
    url: str,
    runtime: RuntimeConfig | None = None,
    *,
    resolver: Resolver = _system_resolver,
    transport: httpx.BaseTransport | None = None,
) -> L3Input:
    """외부 스크립트 Source를 가져오지 않고 HTML 페이지 하나를 수집한다.

    실패해도 예외로 전체 스캔을 중단하지 않고 ``content=None``과 구조화 오류가 든
    ``L3Input``을 반환해 downstream이 '미수집'과 '관측 없음'을 구분하게 한다.
    """
    runtime = runtime or RuntimeConfig()
    errors: list[dict[str, Any]] = []
    try:
        response = _bounded_get(
            url,
            max_bytes=runtime.max_html_bytes,
            runtime=runtime,
            resolver=resolver,
            transport=transport,
        )
        errors.extend(response.errors)
    except (httpx.HTTPError, ValueError, OSError) as exc:
        errors.append(_error("collection", "page_collection_failed", str(exc), url=url))
        return L3Input(
            original_url=url,
            document_url=url,
            html=HTMLInput(content=None),
            collection_errors=errors,
        )

    if response.content_type not in _HTML_CONTENT_TYPES:
        errors.append(
            _error(
                "collection",
                "unsupported_content_type",
                "response is not an HTML content type",
                content_type=response.content_type,
            )
        )

    encoding = response.encoding or "utf-8"
    content = response.body.decode(encoding, errors="replace")
    return L3Input(
        original_url=url,
        document_url=response.url,
        html=HTMLInput(
            content=content,
            content_type=response.content_type,
            encoding=encoding,
            truncated=response.truncated,
        ),
        collection_errors=errors,
    )


def collect_external_script(
    script: ScriptInput,
    runtime: RuntimeConfig,
    *,
    resolver: Resolver = _system_resolver,
    transport: httpx.BaseTransport | None = None,
) -> ScriptInput:
    """명시적으로 허용된 외부 스크립트 하나를 동일한 SSRF 제한으로 수집한다.

    JavaScript MIME type이 아니면 Source를 분석 대상으로 저장하지 않는다. 실제
    수집은 오케스트레이터가 개수 제한을 확인한 후 호출하며 기본 설정에서는 꺼져 있다.
    """
    if script.type != "external" or not script.source_url:
        return script
    if not runtime.fetch_external_scripts:
        return script
    try:
        response = _bounded_get(
            script.source_url,
            max_bytes=runtime.max_script_bytes,
            runtime=runtime,
            resolver=resolver,
            transport=transport,
        )
    except (httpx.HTTPError, ValueError, OSError) as exc:
        script.collection_errors.append(
            _error(
                "script_collection",
                "script_collection_failed",
                str(exc),
                url=script.source_url,
            )
        )
        return script

    if response.content_type not in _JAVASCRIPT_CONTENT_TYPES:
        script.collection_errors.append(
            _error(
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
