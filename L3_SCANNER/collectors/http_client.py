"""Collector가 공유하는 SSRF 방어형 제한 HTTP(S) 클라이언트.

모든 리다이렉트 목적지를 요청 전에 다시 검증하고, 환경 프록시를 사용하지 않으며,
응답을 스트리밍해 설정된 크기 이상 읽지 않는다. 페이지와 외부 JavaScript 수집기는
이 모듈을 공유해 동일한 네트워크 제한을 적용한다.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpcore
import httpx

from L3_SCANNER.policies.runtime import RuntimeConfig
from L3_SCANNER.utils.url import is_http_url

Resolver = Callable[[str, int], Iterable[str]]
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}


def collection_error(
    stage: str, code: str, message: str, **details: Any
) -> dict[str, Any]:
    """수집 단계 오류를 공통 직렬화 구조로 만든다."""
    return {"stage": stage, "code": code, "message": message, "details": details}


def system_resolver(hostname: str, port: int) -> Iterable[str]:
    """호스트의 모든 TCP 주소를 반환해 우회 가능한 비공개 주소도 검사하게 한다."""
    records = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    return tuple(dict.fromkeys(str(record[4][0]) for record in records))


def _is_public_address(value: str) -> bool:
    """인터넷 전역에서 라우팅 가능한 일반 유니캐스트 주소만 허용한다."""
    address = ipaddress.ip_address(value)
    return address.is_global and not address.is_multicast


def _canonical_connection_host(hostname: str) -> str:
    """URL 호스트를 httpx/httpcore가 TCP 연결에 전달하는 ASCII 형태로 맞춘다."""
    try:
        return str(ipaddress.ip_address(hostname))
    except ValueError:
        return hostname.encode("idna").decode("ascii").casefold()


@dataclass(frozen=True, slots=True)
class ResolvedTarget:
    """검증을 통과한 원본 호스트와 실제 연결에 사용할 고정 IP 목록."""

    hostname: str
    port: int
    addresses: tuple[str, ...]


def _resolve_public_http_url(url: str, resolver: Resolver) -> ResolvedTarget:
    """요청 직전 URL 형식과 DNS 결과 전체가 공개 주소인지 검증한다.

    Userinfo를 금지해 호스트 오인 가능성을 줄이고, 여러 DNS 결과 중 하나라도
    비공개 주소이면 요청 전체를 거부한다. 검증된 주소는 실제 TCP 연결에도 그대로
    사용해 검증과 연결 사이 DNS rebinding을 차단한다.
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
        addresses = tuple(
            dict.fromkeys(
                str(ipaddress.ip_address(item))
                for item in resolver(parts.hostname, port)
            )
        )
    except OSError as exc:
        raise ValueError(f"DNS resolution failed: {exc}") from exc
    if not addresses:
        raise ValueError("DNS resolution returned no addresses")
    if any(not _is_public_address(address) for address in addresses):
        raise ValueError("target resolves to a non-public address")
    return ResolvedTarget(_canonical_connection_host(parts.hostname), port, addresses)


class _PinnedNetworkBackend(httpcore.NetworkBackend):
    """원본 호스트를 DNS로 다시 조회하지 않고 검증된 IP에만 연결한다."""

    def __init__(
        self,
        target: ResolvedTarget,
        backend: httpcore.NetworkBackend | None = None,
    ) -> None:
        self._target = target
        self._backend = backend or httpcore.SyncBackend()

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        """호스트·포트가 일치할 때 검증된 IP들에 제한 시간 안에서 연결한다."""
        if host.casefold() != self._target.hostname or port != self._target.port:
            raise httpcore.ConnectError("connection target was not prevalidated")
        deadline = time.monotonic() + timeout if timeout is not None else None
        last_error: httpcore.ConnectError | httpcore.ConnectTimeout | None = None
        for address in self._target.addresses:
            remaining = (
                max(deadline - time.monotonic(), 0.0) if deadline is not None else None
            )
            try:
                return self._backend.connect_tcp(
                    address,
                    port,
                    timeout=remaining,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last_error = exc
        assert last_error is not None
        raise last_error

    def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        """URL Collector에서는 Unix socket 연결을 허용하지 않는다."""
        del path, timeout, socket_options
        raise httpcore.ConnectError("Unix socket connections are not allowed")


class _PinnedHTTPTransport(httpx.HTTPTransport):
    """HTTP 요청의 TCP 연결만 검증된 IP로 고정하는 동기 Transport."""

    def __init__(self, target: ResolvedTarget) -> None:
        super().__init__(trust_env=False)
        self._pool.close()
        self._pool = httpcore.ConnectionPool(
            ssl_context=httpx.create_ssl_context(trust_env=False),
            max_connections=1,
            max_keepalive_connections=0,
            network_backend=_PinnedNetworkBackend(target),
        )


@dataclass(slots=True)
class CollectedResponse:
    """제한 수집 결과와 부분 실패 정보를 Collector 사이에서 전달하는 값 객체."""

    url: str
    body: bytes
    content_type: str | None
    encoding: str | None
    truncated: bool
    status_code: int
    errors: list[dict[str, Any]]


@dataclass(frozen=True, slots=True)
class _RedirectResponse:
    """재검증 후 따라갈 다음 Redirect URL."""

    url: str


def _read_bounded_body(response: httpx.Response, max_bytes: int) -> tuple[bytes, bool]:
    """응답 스트림을 설정 크기까지만 읽고 잘림 여부를 반환한다."""
    chunks: list[bytes] = []
    size = 0
    for chunk in response.iter_bytes():
        remaining = max_bytes - size
        if remaining <= 0:
            return b"".join(chunks), True
        chunks.append(chunk[:remaining])
        size += min(len(chunk), remaining)
        if len(chunk) > remaining:
            return b"".join(chunks), True
    return b"".join(chunks), False


def _normalized_content_type(response: httpx.Response) -> str | None:
    """Content-Type 헤더에서 MIME type만 소문자로 정규화한다."""
    value = response.headers.get("content-type")
    return value.split(";", 1)[0].strip().lower() if value else None


def _final_response(response: httpx.Response, max_bytes: int) -> CollectedResponse:
    """최종 HTTP 응답을 크기가 제한된 Collector 결과로 변환한다."""
    body, truncated = _read_bounded_body(response, max_bytes)
    errors = []
    if response.status_code >= 400:
        errors.append(
            collection_error(
                "collection",
                "http_error_status",
                "server returned an HTTP error status",
                status_code=response.status_code,
            )
        )
    return CollectedResponse(
        url=str(response.url),
        body=body,
        content_type=_normalized_content_type(response),
        encoding=response.encoding,
        truncated=truncated,
        status_code=response.status_code,
        errors=errors,
    )


def _redirect_without_location(url: str, status_code: int) -> CollectedResponse:
    """Location이 없는 Redirect를 부분 수집 결과로 보존한다."""
    return CollectedResponse(
        url=url,
        body=b"",
        content_type=None,
        encoding=None,
        truncated=False,
        status_code=status_code,
        errors=[
            collection_error(
                "collection",
                "redirect_without_location",
                "redirect response has no Location",
            )
        ],
    )


def _request_once(
    url: str,
    *,
    target: ResolvedTarget,
    max_bytes: int,
    runtime: RuntimeConfig,
    transport: httpx.BaseTransport | None,
) -> CollectedResponse | _RedirectResponse:
    """검증된 대상에 한 번 요청하고 최종 응답 또는 다음 Redirect를 반환한다."""
    active_transport = (
        transport if transport is not None else _PinnedHTTPTransport(target)
    )
    with httpx.Client(
        follow_redirects=False,
        timeout=runtime.request_timeout_seconds,
        transport=active_transport,
        trust_env=False,
        headers={"User-Agent": "L3-Scanner/1.0"},
    ) as client:
        with client.stream("GET", url) as response:
            if response.status_code not in _REDIRECT_STATUSES:
                return _final_response(response, max_bytes)
            location = response.headers.get("location")
            if not location:
                return _redirect_without_location(url, response.status_code)
            return _RedirectResponse(urljoin(url, location))


def bounded_get(
    url: str,
    *,
    max_bytes: int,
    runtime: RuntimeConfig,
    resolver: Resolver,
    transport: httpx.BaseTransport | None,
) -> CollectedResponse:
    """리다이렉트·시간·본문 크기를 제한하며 응답 하나를 수집한다.

    ``httpx``의 자동 리다이렉트를 끄고 각 Location을 다시 SSRF 검증한다. 본문은
    ``max_bytes``까지만 보존하며 초과 여부를 ``truncated``로 명시한다.
    """
    current_url = url
    for redirect_count in range(runtime.max_redirects + 1):
        target = _resolve_public_http_url(current_url, resolver)
        outcome = _request_once(
            current_url,
            target=target,
            max_bytes=max_bytes,
            runtime=runtime,
            transport=transport,
        )
        if isinstance(outcome, CollectedResponse):
            return outcome
        if redirect_count >= runtime.max_redirects:
            raise ValueError("redirect limit exceeded")
        current_url = outcome.url

    raise RuntimeError("bounded request loop ended unexpectedly")
