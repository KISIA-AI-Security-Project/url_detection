"""HTTP(S) URL과 DNS 결과를 검증하고 실제 연결 주소를 고정한다."""

from __future__ import annotations

import ipaddress
import socket
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpcore
import httpx

Resolver = Callable[[str, int], Iterable[str]]


def system_resolver(hostname: str, port: int) -> Iterable[str]:
    """호스트의 모든 TCP 주소를 중복 없이 반환한다."""
    records = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    return tuple(dict.fromkeys(str(record[4][0]) for record in records))


def _is_public_address(value: str) -> bool:
    address = ipaddress.ip_address(value)
    return address.is_global and not address.is_multicast


def _canonical_connection_host(hostname: str) -> str:
    try:
        return str(ipaddress.ip_address(hostname))
    except ValueError:
        return hostname.encode("idna").decode("ascii").casefold()


@dataclass(frozen=True, slots=True)
class ResolvedTarget:
    """검증된 URL 호스트와 실제 TCP 연결에 사용할 공개 IP 목록."""

    hostname: str
    port: int
    addresses: tuple[str, ...]


def resolve_public_http_url(url: str, resolver: Resolver) -> ResolvedTarget:
    """요청 직전 URL과 DNS 결과를 검증해 SSRF 및 DNS rebinding을 막는다."""
    parts = urlsplit(url)
    if parts.scheme.casefold() not in {"http", "https"} or not parts.hostname:
        raise ValueError("only absolute HTTP(S) URLs are allowed")
    if parts.username is not None or parts.password is not None:
        raise ValueError("URL user information is not allowed")
    try:
        port = parts.port or (443 if parts.scheme.casefold() == "https" else 80)
    except ValueError as exc:
        raise ValueError("URL port is malformed") from exc
    try:
        addresses = tuple(
            dict.fromkeys(
                str(ipaddress.ip_address(item))
                for item in resolver(parts.hostname, port)
            )
        )
    except (OSError, ValueError) as exc:
        raise ValueError(f"DNS resolution failed: {exc}") from exc
    if not addresses:
        raise ValueError("DNS resolution returned no addresses")
    if any(not _is_public_address(address) for address in addresses):
        raise ValueError("target resolves to a non-public address")
    return ResolvedTarget(_canonical_connection_host(parts.hostname), port, addresses)


class PinnedNetworkBackend(httpcore.NetworkBackend):
    """검증된 IP 외의 TCP 또는 Unix socket 연결을 거부한다."""

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
        del path, timeout, socket_options
        raise httpcore.ConnectError("Unix socket connections are not allowed")


class PinnedHTTPTransport(httpx.HTTPTransport):
    """HTTP 연결을 사전 검증된 IP에 고정하는 동기 Transport."""

    def __init__(self, target: ResolvedTarget) -> None:
        super().__init__(trust_env=False)
        self._pool.close()
        self._pool = httpcore.ConnectionPool(
            ssl_context=httpx.create_ssl_context(trust_env=False),
            max_connections=1,
            max_keepalive_connections=0,
            network_backend=PinnedNetworkBackend(target),
        )
