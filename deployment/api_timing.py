"""Opt-in stdlib timing for API handlers; never part of the public response.

Spans may overlap or contain one another. Their sum is not CPU time or total
request time. Lambda INIT and API Gateway/authorizer time are measured elsewhere.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
import json
import os
import re
from threading import Lock
from time import perf_counter
from uuid import uuid4

_ACTIVE = ContextVar('api_timing', default=None)
_ENVIRONMENT = None
_INVOCATIONS = 0
_FIELDS = {'artifact', 'bytes', 'retries', 'reused', 'count'}


class Trace:
    def __init__(self, metadata):
        self.metadata = metadata
        self.started = perf_counter()
        self.events = []
        self.lock = Lock()
        self.dropped = 0

    def identify(self, *, job_id=None, attempt=None):
        if isinstance(job_id, str) and re.fullmatch('[0-9a-f]{32}', job_id):
            self.metadata['job_id'] = job_id
        if isinstance(attempt, int) and not isinstance(attempt, bool) and attempt > 0:
            self.metadata['attempt'] = attempt

    @contextmanager
    def span(self, name, **fields):
        started = perf_counter()
        row = {'name': name, 'start_ms': round((started - self.started) * 1000, 3)}
        details = {key: value for key, value in fields.items() if key in _FIELDS}
        try:
            yield details
        except BaseException as exc:
            row.update(success=False, error_type=type(exc).__name__)
            raise
        else:
            row['success'] = True
        finally:
            row['duration_ms'] = round((perf_counter() - started) * 1000, 3)
            row.update({key: value for key, value in details.items() if key in _FIELDS})
            with self.lock:
                if len(self.events) < 256:
                    self.events.append(row)
                else:
                    self.dropped += 1

    def finish(self, success):
        value = {'schema_version': 'lambda-performance-1', **self.metadata,
                 'success': success,
                 'handler_observed_ms': round((perf_counter() - self.started) * 1000, 3),
                 'spans': sorted(self.events, key=lambda row: row['start_ms']),
                 'dropped_spans': self.dropped}
        try:
            print(json.dumps(value, ensure_ascii=False, separators=(',', ':')), flush=True)
        except Exception:
            pass  # Diagnostic output must not alter the API result.


def current_trace():
    return _ACTIVE.get()


@contextmanager
def span(name, **fields):
    trace = current_trace()
    if trace is None:
        yield {}
    else:
        with trace.span(name, **fields) as details:
            yield details


@contextmanager
def invocation(event, aws_context, role):
    global _ENVIRONMENT, _INVOCATIONS
    if os.environ.get('EVIDENCE_TIMING') != '1':
        yield None
        return
    if _ENVIRONMENT is None:
        _ENVIRONMENT = uuid4().hex
    _INVOCATIONS += 1
    trace = Trace({'role': role, 'operation': role,
                   'request_id': getattr(aws_context, 'aws_request_id', None),
                   'started_at': datetime.now(timezone.utc).isoformat(),
                   'job_id': None, 'attempt': None,
                   'environment_id': _ENVIRONMENT, 'invocation_number': _INVOCATIONS})
    api_request_id = (event.get('requestContext') or {}).get('requestId')
    if isinstance(api_request_id, str) and re.fullmatch('[0-9A-Za-z-]{1,128}', api_request_id):
        trace.metadata['api_request_id'] = api_request_id
    trace.identify(job_id=(event.get('pathParameters') or {}).get('scanId') or event.get('job_id'),
                   attempt=event.get('attempt'))
    token = _ACTIVE.set(trace)
    success = False
    try:
        yield trace
        success = True
    finally:
        _ACTIVE.reset(token)
        trace.finish(success)
