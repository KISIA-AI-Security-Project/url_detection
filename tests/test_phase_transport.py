"""Timeout phase must remain visible after an HTTPS request was written."""

import http.client

import pytest

from evidence_pipeline.phase_transport import PhaseHTTPSConnection, PhaseTrace


def test_response_header_timeout_keeps_completed_write(monkeypatch):
    class Socket:
        def sendall(self, data):
            assert data == b'POST /v1/messages HTTP/1.1\r\n\r\n'

    def no_headers(_connection):
        raise TimeoutError('simulated header wait')

    monkeypatch.setattr(http.client.HTTPSConnection, 'getresponse', no_headers)
    trace = PhaseTrace()
    connection = PhaseHTTPSConnection('provider.example', trace=trace, timeout=1)
    connection.sock = Socket()
    connection._tls_established = True
    body = b'POST /v1/messages HTTP/1.1\r\n\r\n'
    connection.send(body)
    with pytest.raises(TimeoutError):
        connection.getresponse()
    saved = trace.snapshot()
    assert saved['request_bytes_written'] == len(body)
    assert saved['response_headers_received'] is False
    assert saved['failure_phase'] == 'response_headers'
    assert saved['exception_type'] == 'TimeoutError'
