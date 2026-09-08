from __future__ import annotations

from collections.abc import Iterable

import httpcore
import pytest

from url_collector.ssrf import (
    PinnedNetworkBackend,
    ResolvedTarget,
    resolve_public_http_url,
)


class DummyStream(httpcore.NetworkStream):
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


class RecordingBackend(httpcore.NetworkBackend):
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
        return DummyStream()

    def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        del path, timeout, socket_options
        raise AssertionError("Unix sockets must not be used")


def test_pinned_backend_connects_to_validated_ip() -> None:
    recording = RecordingBackend()
    backend = PinnedNetworkBackend(
        ResolvedTarget("example.com", 443, ("93.184.216.34",)), recording
    )

    backend.connect_tcp("example.com", 443)

    assert recording.connected_host == "93.184.216.34"


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "javascript:alert(1)",
        "https://user:password@example.com/",
        "not-a-url",
    ],
)
def test_rejects_non_http_or_ambiguous_urls(url: str) -> None:
    with pytest.raises(ValueError):
        resolve_public_http_url(url, lambda hostname, port: ["93.184.216.34"])
