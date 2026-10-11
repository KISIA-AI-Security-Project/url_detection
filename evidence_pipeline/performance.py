"""Opt-in timing logs, separate from evidence, model input and public results.

Spans are nested/overlapping wall times, never additive CPU accounting. An
observer passed to scanner workers is invocation-bound and ignores late work.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
import json
import os
from threading import Lock
from time import perf_counter
from uuid import uuid4

_ACTIVE = ContextVar('evidence_performance', default=None)
_ENVIRONMENT = None
_INVOCATIONS = 0
_FIELDS = {'artifact', 'bytes', 'retries', 'reused'}


class Trace:
    def __init__(self, metadata):
        self.metadata = metadata
        self.started = perf_counter()
        self.events = []
        self.lock = Lock()
        self.closed = False
        self.dropped = 0

    @contextmanager
    def span(self, name, **fields):
        started = perf_counter()
        row = {'name': name, 'start_ms': round((started - self.started) * 1000, 3)}
        details = {k: v for k, v in fields.items() if k in _FIELDS}
        try:
            yield details
        except BaseException as exc:
            row.update(success=False, error_type=type(exc).__name__)
            raise
        else:
            row['success'] = True
        finally:
            row['duration_ms'] = round((perf_counter() - started) * 1000, 3)
            row.update({k: v for k, v in details.items() if k in _FIELDS})
            with self.lock:
                if not self.closed:
                    if len(self.events) < 256:
                        self.events.append(row)
                    else:
                        self.dropped += 1

    def finish(self, success):
        with self.lock:
            self.closed = True
            value = {'schema_version': 'lambda-performance-1', **self.metadata,
                     'success': success, 'handler_observed_ms': round((perf_counter() - self.started) * 1000, 3),
                     'spans': sorted(self.events, key=lambda row: row['start_ms']),
                     'dropped_spans': self.dropped}
        try:
            print(json.dumps(value, ensure_ascii=False, separators=(',', ':')), flush=True)
        except Exception:
            pass  # Diagnostic output must not change the service result.


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


def timed(name):
    def decorate(function):
        @wraps(function)
        def run(*args, **kwargs):
            with span(name):
                return function(*args, **kwargs)
        return run
    return decorate


@contextmanager
def invocation(event, aws_context, role):
    global _ENVIRONMENT, _INVOCATIONS
    # A SnapStart snapshot may become several execution environments. Generate
    # this diagnostic identity at the first invocation, never during snapshot.
    if _ENVIRONMENT is None:
        _ENVIRONMENT = uuid4().hex
    _INVOCATIONS += 1
    if os.environ.get('EVIDENCE_TIMING') != '1':
        yield None
        return
    # Join identifiers only; never log URL, event body, raw evidence or full keys.
    operation = (event['operation'] if role == 'context' and
                 event.get('operation') in ('activity', 'activity_context') else role)
    trace = Trace({'role': role, 'operation': operation,
                   'request_id': getattr(aws_context, 'aws_request_id', None),
                   'job_id': event.get('job_id'), 'attempt': event.get('attempt'),
                   'environment_id': _ENVIRONMENT, 'invocation_number': _INVOCATIONS})
    token = _ACTIVE.set(trace)
    success = False
    try:
        yield trace
        success = True
    finally:
        _ACTIVE.reset(token)
        trace.finish(success)
