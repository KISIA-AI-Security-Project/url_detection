"""I/O overlap keeps validation, single-call and public commit boundaries."""
from copy import deepcopy
import json
from threading import Barrier, Lock

import pytest

from evidence_pipeline import aws_fast_result, performance
from evidence_pipeline.aws_runtime import PipelineServiceError
from test_fast_result_contract import MemoryStore, build_persisted, response_for


class ObservedStore(MemoryStore):
    def __init__(self, source, paths, *, failures=(), invalid_context=False):
        self.values = dict(source.values)
        self.paths = paths
        self.failures = set(failures)
        self.invalid_context = invalid_context
        self.read_barrier = Barrier(3)
        self.write_barrier = Barrier(4)
        self.lock = Lock()
        self.finished_reads = set()
        self.finished_writes = set()
        self.worker_traces = []
        self.reads = {paths['context'], paths['result'], paths['activity']}
        self.writes = {paths[name] for name in ('response', 'diagnostics', 'judgment', 'handoff')}

    def get(self, key, optional=False):
        if key in self.reads:
            self.worker_traces.append(performance.current_trace())
            self.read_barrier.wait(timeout=3)
            with self.lock:
                self.finished_reads.add(key)
        if key == self.paths['activity'] and self.invalid_context:
            raise OSError('later_activity_read_error')
        value = super().get(key, optional)
        if key == self.paths['context'] and self.invalid_context:
            value['context_revision'] = 'mismatch'
        return value

    def put(self, key, value, exclusive=False):
        if key in self.writes:
            self.worker_traces.append(performance.current_trace())
            self.write_barrier.wait(timeout=3)
            try:
                if key in self.failures:
                    raise OSError(key)
                return super().put(key, value, exclusive)
            finally:
                with self.lock:
                    self.finished_writes.add(key)
        if key == self.paths['result']:
            assert self.finished_writes == self.writes
            assert not self.failures
        return super().put(key, value, exclusive)


class RecordedGateway:
    def __init__(self, store):
        self.store = store
        self.last_request_body = None
        self.last_response = None
        self.calls = 0

    def _payload(self, prompt, body):
        return {'system': prompt, 'messages': [{'role': 'user', 'content': body}]}

    def __call__(self, prompt, body):
        self.calls += 1
        paths = self.store.paths
        assert paths['claim'] in self.store.values
        self.last_request_body = json.dumps(self._payload(prompt, body), ensure_ascii=False,
                                           separators=(',', ':')).encode('utf-8')
        assert self.store.values[paths['request']] == self.last_request_body
        self.last_response = {'captured': 'offline provider response'}
        return deepcopy(response_for('login'))


def case(**kwargs):
    event, source, output, _ = build_persisted('login')
    event = {**event, 'context_key': output['final_key'], 'context_sha256': output['context_sha256']}
    paths = aws_fast_result.keys(event['job_id'], event['attempt'])
    paths['activity'] = f"records/{event['job_id']}/{event['attempt']}/final/url-activity.json"
    if 'failure_names' in kwargs:
        kwargs['failures'] = [paths[name] for name in kwargs.pop('failure_names')]
    store = ObservedStore(source, paths, **kwargs)
    return event, store, RecordedGateway(store)


def test_independent_io_overlaps_and_keeps_invocation_trace_and_commit_order(monkeypatch, capsys):
    event, store, gateway = case()
    monkeypatch.setenv('EVIDENCE_TIMING', '1')
    with performance.invocation(event, None, 'judgment') as trace:
        result = aws_fast_result.run_judgment(event, store, lambda: gateway)
    assert result['judgment_status'] == 'accepted'
    assert gateway.calls == 1
    assert store.finished_reads == store.reads
    assert store.finished_writes == store.writes
    assert len(store.worker_traces) == 7 and all(value is trace for value in store.worker_traces)
    assert json.loads(capsys.readouterr().out)['success']


@pytest.mark.parametrize('failed', ['response', 'diagnostics', 'judgment', 'handoff'])
def test_any_internal_put_failure_prevents_public_commit_and_second_provider_call(failed):
    event, store, gateway = case(failure_names=[failed])
    with pytest.raises(OSError, match=failed if failed != 'diagnostics' else 'link-diagnostics'):
        aws_fast_result.run_judgment(event, store, lambda: gateway)
    assert gateway.calls == 1 and store.paths['result'] not in store.values
    assert store.finished_writes == store.writes  # No operation outlives the invocation.
    with pytest.raises(RuntimeError, match='immutable_artifact_conflict'):
        aws_fast_result.run_judgment(event, store, lambda: pytest.fail('claim must block retry'))
    assert gateway.calls == 1


def test_read_validation_and_write_failure_priority_are_independent_of_completion_order():
    event, store, gateway = case(invalid_context=True)
    with pytest.raises(PipelineServiceError, match='fast_context_binding_mismatch'):
        aws_fast_result.run_judgment(event, store, lambda: gateway)
    assert store.finished_reads == store.reads
    assert store.paths['claim'] not in store.values and gateway.calls == 0
    event, store, gateway = case(failure_names=['response', 'diagnostics'])
    with pytest.raises(OSError, match='provider-response'):
        aws_fast_result.run_judgment(event, store, lambda: gateway)
    assert store.finished_writes == store.writes and store.paths['result'] not in store.values
