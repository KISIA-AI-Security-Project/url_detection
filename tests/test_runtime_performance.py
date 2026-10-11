"""Runtime lifecycle and separate diagnostics; URL semantics use existing fixtures."""
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from evidence_pipeline import aws_clients, aws_runtime, performance


def test_handler_reuses_client_but_not_store_or_request_data(monkeypatch):
    clients, stores = [], []
    sdk = SimpleNamespace(get_object=lambda **kwargs: {'Body': io.BytesIO(b'{}')})
    def client(service):
        assert service == 's3'
        clients.append(sdk)
        return sdk
    monkeypatch.setattr(aws_clients, '_S3', None)
    monkeypatch.setitem(sys.modules, 'boto3', SimpleNamespace(client=client))
    monkeypatch.setenv('EVIDENCE_ROLE', 'context')
    monkeypatch.setenv('OUTPUT_BUCKET', aws_runtime.BUCKET)
    def activity(event, store):
        stores.append(store)
        return {'job': event['job_id'], 'value': store.get('records/'+event['job_id']+'/1/l0/l0.json')}
    monkeypatch.setattr(aws_runtime, 'activity', activity)
    for job in ('one', 'two'):
        assert aws_runtime.handler({'operation': 'activity', 'job_id': job}) == {'job': job, 'value': {}}
    assert len(clients) == 1
    assert stores[0] is not stores[1] and stores[0].s3 is stores[1].s3
    assert aws_clients.LazyS3().get_object(Key='unused')['Body'].read() == b'{}'
    assert len(clients) == 1


def test_timing_success_error_and_late_worker_do_not_change_results(monkeypatch, capsys):
    monkeypatch.setenv('EVIDENCE_TIMING', '1')
    event = {'job_id': 'timing-test', 'attempt': 1, 'url': 'https://example.test/private?token=secret'}
    with performance.invocation(event, SimpleNamespace(aws_request_id='request-1'), 'context') as trace:
        with performance.span('context.build'):
            result = {'retained': True}
    assert result == {'retained': True}
    with trace.span('late-worker'):
        pass
    failure = ValueError('original-failure')
    with pytest.raises(ValueError) as caught:
        with performance.invocation(event, None, 'context'):
            with performance.span('context.build'):
                raise failure
    assert caught.value is failure and performance.current_trace() is None
    output = capsys.readouterr().out
    first, second = map(json.loads, output.splitlines())
    assert first['success'] is True and second['success'] is False
    assert first['spans'][0]['name'] == 'context.build'
    assert second['spans'][0]['error_type'] == 'ValueError'
    assert all(row['name'] != 'late-worker' for row in trace.events)
    assert 'private' not in output and 'secret' not in output and 'original-failure' not in output
    monkeypatch.setattr('builtins.print', lambda *a, **k: (_ for _ in ()).throw(OSError('log unavailable')))
    with performance.invocation(event, None, 'context'):
        pass


def test_runtime_import_is_light_and_public_exports_remain_available():
    repo = Path(__file__).resolve().parents[1]
    code = '''
import importlib, sys
import evidence_pipeline as ep
import evidence_pipeline.aws_runtime
assert 'boto3' not in sys.modules
assert 'evidence_pipeline.fast_context' not in sys.modules
assert 'evidence_pipeline.pipeline' not in sys.modules
assert 'evidence_pipeline.gateway' not in sys.modules
assert set(ep.__all__) == {'build_record','build_context','build_l1_context','build_text_context',
 'render_text_context','build_html_text_context','build_javascript_text_context',
 'build_l3_content_text_context','build_fast_context','FastPipeline'}
for name in ep.__all__:
 assert getattr(ep,name) is getattr(importlib.import_module('.'+ep._EXPORTS[name],ep.__name__),name)
'''
    completed = subprocess.run([sys.executable, '-B', '-c', code], cwd=repo,
                               capture_output=True, text=True, env={**os.environ, 'PYTHONPATH': str(repo)})
    assert completed.returncode == 0, completed.stderr
