from __future__ import annotations

from collections.abc import Iterable

import httpcore

from L3_SCANNER.collectors.http_client import (
    ResolvedTarget,
    _PinnedNetworkBackend,
)


class _DummyStream(httpcore.NetworkStream):
    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        del max_bytes, timeout
        return b""

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        del buffer, timeout

    def close(self) -> None:
        return None

    def start_tls(
        self,
        ssl_context: object,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.NetworkStream:
        del ssl_context, server_hostname, timeout
        return self


class _RecordingBackend(httpcore.NetworkBackend):
    def __init__(self) -> None:
        self.connected_host: str | None = None

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        del port, timeout, local_address, socket_options
        self.connected_host = host
        return _DummyStream()

    def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        del path, timeout, socket_options
        raise AssertionError("Unix socket must not be used")


def test_pinned_backend_connects_to_validated_ip_without_dns_lookup() -> None:
    recording = _RecordingBackend()
    backend = _PinnedNetworkBackend(
        ResolvedTarget("example.com", 443, ("93.184.216.34",)),
        recording,
    )

    backend.connect_tcp("example.com", 443)

    assert recording.connected_host == "93.184.216.34"
