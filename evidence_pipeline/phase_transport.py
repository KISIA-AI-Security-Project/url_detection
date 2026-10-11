"""Phase timing for the isolated HTTPS model request; no URL body or key is logged."""

import http.client
import socket
import time
import urllib.request


class PhaseTrace:
    def __init__(self):
        self.started = time.monotonic()
        self.phase = 'not_started'
        self.events = []
        self.request_bytes_written = 0
        self.response_headers_received = False
        self.failure_phase = None
        self.exception_type = None

    def enter(self, phase):
        self.phase = phase
        self.events.append({'phase': phase,
                            'elapsed_ms': round((time.monotonic() - self.started) * 1000, 1)})

    def failed(self, exc):
        if self.failure_phase is None:
            self.failure_phase = self.phase
            self.exception_type = type(exc).__name__

    def snapshot(self):
        return {'last_phase': self.phase, 'failure_phase': self.failure_phase,
                'exception_type': self.exception_type,
                'request_bytes_written': self.request_bytes_written,
                'response_headers_received': self.response_headers_received,
                'elapsed_ms': round((time.monotonic() - self.started) * 1000, 1),
                'events': self.events[:24]}


class PhaseHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, *, trace, **kwargs):
        super().__init__(host, **kwargs)
        self.trace = trace
        self._create_connection = self._connect_socket
        self._tls_established = False

    def _connect_socket(self, address, timeout, source_address):
        host, port = address
        self.trace.enter('dns_lookup')
        try:
            addresses = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
        except Exception as exc:
            self.trace.failed(exc)
            raise
        self.trace.enter('tcp_connect')
        last_error = None
        for family, kind, protocol, _, sockaddr in addresses:
            sock = None
            try:
                sock = socket.socket(family, kind, protocol)
                sock.settimeout(timeout)
                if source_address:
                    sock.bind(source_address)
                sock.connect(sockaddr)
                return sock
            except OSError as exc:
                last_error = exc
                if sock is not None:
                    sock.close()
        if last_error is None:
            last_error = OSError('DNS returned no usable address')
        self.trace.failed(last_error)
        raise last_error

    def connect(self):
        try:
            http.client.HTTPConnection.connect(self)
            self.trace.enter('tls_handshake')
            self.sock = self._context.wrap_socket(
                self.sock, server_hostname=self._tunnel_host or self.host)
            self._tls_established = True
        except Exception as exc:
            self.trace.failed(exc)
            raise

    def send(self, data):
        try:
            if self.sock is None:
                self.connect()
            self.trace.enter('request_write' if self._tls_established else 'proxy_tunnel')
            super().send(data)
            if self._tls_established and isinstance(data, (bytes, bytearray)):
                self.trace.request_bytes_written += len(data)
        except Exception as exc:
            self.trace.failed(exc)
            raise

    def getresponse(self):
        self.trace.enter('response_headers')
        try:
            response = super().getresponse()
            self.trace.response_headers_received = True
            self.trace.enter('response_body')
            return response
        except Exception as exc:
            self.trace.failed(exc)
            raise


class PhaseHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, trace):
        super().__init__()
        self.trace = trace

    def https_open(self, request):
        return self.do_open(
            lambda host, **kwargs: PhaseHTTPSConnection(host, trace=self.trace, **kwargs),
            request, context=self._context)


def traced_opener(trace, no_redirect_handler):
    return urllib.request.build_opener(no_redirect_handler, PhaseHTTPSHandler(trace)).open
