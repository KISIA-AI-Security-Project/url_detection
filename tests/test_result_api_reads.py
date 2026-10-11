"""Result polling: saved public bodies, request-local reads, and I/O failures."""
from collections import Counter
from copy import deepcopy
import importlib.util
from hashlib import sha256
import io
import json
from pathlib import Path
import sys
from threading import Barrier
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[4]
REPO = Path(__file__).resolve().parents[1]
AUDIT = ROOT / 'evaluation/remediation-20261005/performance-round4/frontend-route-audit'
ACTUAL = ROOT / ('evaluation/remediation-20261005/performance-round3/aws-live/'
                 'final-prepared-actual/run-sfn-ec2-final-pc/jobs')


class S3Error(Exception):
    def __init__(self, code, status):
        super().__init__(code)
        self.response = {'Error': {'Code': code}, 'ResponseMetadata': {'HTTPStatusCode': status}}


class S3:
    def __init__(self, objects):
        self.objects = {key: list(value) if isinstance(value, list) else value
                        for key, value in objects.items()}
        self.calls = []
        self.bodies = []

    def get_object(self, **kw):
        key = kw['Key']
        self.calls.append(key)
        value = self.objects.get(key, S3Error('NoSuchKey', 404))
        if isinstance(value, list):
            value = value.pop(0)
        if isinstance(value, BaseException):
            raise value
        body = io.BytesIO(value)
        self.bodies.append(body)
        return {'Body': body, 'ResponseMetadata': {'RetryAttempts': 0}}


def recorded(number='405'):
    job = 'a50914ff202610050000000000000' + number
    folder = ACTUAL / job
    ledger = json.loads((folder / 'ddb.json').read_text(encoding='utf-8'))
    if 'Item' in ledger:
        ledger = ledger['Item']
    else:
        def dynamo(value):
            if isinstance(value, str):
                return {'S': value}
            if isinstance(value, bool):
                return {'BOOL': value}
            if value is None:
                return {'NULL': True}
            if isinstance(value, (int, float)):
                return {'N': str(value)}
            if isinstance(value, list):
                return {'L': [dynamo(v) for v in value]}
            return {'M': {key: dynamo(v) for key, v in value.items()}}
        ledger = {key: dynamo(value) for key, value in ledger.items()}
    prefix = f'records/{job}/1/fast/'
    objects = {prefix + name: (folder / 's3' / (prefix + name)).read_bytes()
               for name in ('result.json', 'pending.json')}
    expected = json.loads((folder / 'public-result.json').read_text(encoding='utf-8'))
    return job, ledger, prefix, objects, expected


def load_app(monkeypatch, ledger, objects, *, before=False, source=None):
    s3 = S3(objects)
    ddb = SimpleNamespace(get_item=lambda **_: {'Item': deepcopy(ledger)})
    monkeypatch.setenv('JOBS_TABLE', 'offline-jobs')
    monkeypatch.setenv('EVIDENCE_BUCKET', 'offline-bucket')
    monkeypatch.setitem(sys.modules, 'boto3', SimpleNamespace(
        client=lambda name: ddb if name == 'dynamodb' else s3))
    path = source or (AUDIT / 'result-before.py' if before else REPO / 'deployment/result/app.py')
    spec = importlib.util.spec_from_file_location('result_before' if before else 'result_candidate', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, s3


def call(module, job):
    return module.handler({'pathParameters': {'scanId': job}}, SimpleNamespace(aws_request_id='offline-request'))


@pytest.mark.parametrize('number', ['405', '406'])
def test_actual_public_response_unchanged_and_one_get(monkeypatch, number):
    job, ledger, prefix, objects, expected = recorded(number)
    old, _ = load_app(monkeypatch, ledger, objects, before=True)
    new, s3 = load_app(monkeypatch, ledger, objects)
    assert call(new, job) == call(old, job)
    assert json.loads(call(new, job)['body']) == expected
    assert s3.calls == [prefix + 'result.json'] * 2
    assert all(body.closed for body in s3.bodies)


def test_final_before_ledger_update_retains_priority(monkeypatch):
    job, ledger, prefix, objects, expected = recorded()
    ledger['status'] = {'S': 'FINAL_DONE'}
    ledger['fast_result_key'] = {'S': prefix + 'pending.json'}
    app, s3 = load_app(monkeypatch, ledger, objects)
    assert json.loads(call(app, job)['body']) == expected
    assert s3.calls == [prefix + 'result.json']


def test_confirmed_missing_final_is_once_per_poll_not_between_polls(monkeypatch):
    job, ledger, prefix, objects, expected = recorded()
    ledger['fast_result_key'] = {'S': prefix + 'result.json'}
    old, old_s3 = load_app(monkeypatch, ledger, {}, before=True)
    new, new_s3 = load_app(monkeypatch, ledger, {})
    assert call(new, job) == call(old, job)
    assert new_s3.calls == [prefix + 'result.json']
    assert old_s3.calls == [prefix + 'result.json'] * 2
    new_s3.objects.update(objects)
    assert json.loads(call(new, job)['body']) == expected
    assert new_s3.calls == [prefix + 'result.json'] * 2


@pytest.mark.parametrize('first', [S3Error('AccessDenied', 403), TimeoutError('offline'), b'{invalid'])
def test_read_errors_do_not_suppress_existing_second_read(monkeypatch, first):
    job, ledger, prefix, objects, expected = recorded()
    objects[prefix + 'result.json'] = [first, objects[prefix + 'result.json']]
    old, old_s3 = load_app(monkeypatch, ledger, objects, before=True)
    new, new_s3 = load_app(monkeypatch, ledger, objects)
    response = call(new, job)
    assert response == call(old, job)
    assert json.loads(response['body']) == expected
    assert old_s3.calls == new_s3.calls == [prefix + 'result.json'] * 2


@pytest.mark.parametrize('case', ['pending', 'failed_with_pending', 'invalid', 'not_requested', 'bad_key'])
def test_existing_public_failure_and_pending_semantics_unchanged(monkeypatch, case):
    job, ledger, prefix, objects, _ = recorded()
    ledger['fast_result_key'] = {'S': prefix + 'pending.json'}
    if case in ('pending', 'failed_with_pending', 'not_requested'):
        del objects[prefix + 'result.json']
    if case == 'pending':
        ledger['status'] = {'S': 'FINAL_DONE'}
    elif case == 'failed_with_pending':
        ledger['status'] = {'S': 'FAILED'}
    elif case == 'invalid':
        objects[prefix + 'result.json'] = b'{}'
    elif case == 'not_requested':
        objects.clear()
        ledger['status'] = {'S': 'TARGET_BLOCKED'}
        ledger['judgment_status'] = {'S': 'not_requested'}
    else:
        ledger['fast_result_key'] = {'S': 'records/wrong/result.json'}
    old, _ = load_app(monkeypatch, ledger, objects, before=True)
    new, s3 = load_app(monkeypatch, ledger, objects)
    assert call(new, job) == call(old, job)
    assert max(Counter(s3.calls).values(), default=0) <= 1


def test_independent_reads_overlap_without_losing_invocation_trace(monkeypatch, capsys):
    from deployment.api_timing import invocation
    monkeypatch.setenv('EVIDENCE_TIMING', '1')
    job, ledger, _, _, _ = recorded()
    app, s3 = load_app(monkeypatch, ledger, {'one': b'{"n":1}', 'two': b'{"n":2}'})
    get = s3.get_object
    barrier = Barrier(2)
    def paired_get(**kw):
        barrier.wait(timeout=5)
        return get(**kw)
    s3.get_object = paired_get
    with invocation({'job_id': job}, None, 'result'):
        token = app._REQUEST_READS.set(app._ReadCache())
        try:
            assert app._load_many({'one': (app._load, 'one'), 'two': (app._load, 'two')}) == {
                'one': {'n': 1}, 'two': {'n': 2}}
        finally:
            app._REQUEST_READS.reset(token)
    trace = json.loads(capsys.readouterr().out)
    assert len([row for row in trace['spans'] if row['name'] == 'result.s3.get']) == 2
    assert trace['dropped_spans'] == 0 and trace['job_id'] == job


def test_api_timing_has_no_request_body_or_auth_and_can_be_disabled(monkeypatch, capsys):
    from deployment.api_timing import invocation, span
    event = {'headers': {'Authorization': 'Bearer offline-sensitive'},
             'requestContext': {'requestId': 'safe-request-123'},
             'body': '{"url":"https://private-input.example/"}'}
    monkeypatch.setenv('EVIDENCE_TIMING', '1')
    with invocation(event, None, 'gate') as trace:
        trace.identify(job_id='a' * 32, attempt=1)
        with span('gate.test', url='never-log', count=1) as row:
            row['token'] = 'never-log'
    logged = capsys.readouterr().out
    assert 'offline-sensitive' not in logged and 'private-input' not in logged and 'never-log' not in logged
    assert json.loads(logged)['attempt'] == 1
    assert json.loads(logged)['api_request_id'] == 'safe-request-123'
    monkeypatch.delenv('EVIDENCE_TIMING')
    with invocation(event, None, 'gate'):
        with span('gate.test'):
            pass
    assert capsys.readouterr().out == ''


@pytest.mark.parametrize('dual_stack', [True, False], ids=['actual-legacy-A-AAAA', 'current-A-only'])
def test_existing_reachability_contracts_remain_terminal(monkeypatch, dual_stack):
    proof = json.loads((AUDIT.parent / 'independent/legacy-result-compatibility.json').read_text(encoding='utf-8'))
    decision, ledger = deepcopy(proof['decision']), deepcopy(proof['ledger'])
    if not dual_stack:
        decision['l1_address_observation'].pop('AAAA')
    raw = json.dumps(decision, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()
    ledger['url_activity_sha256'] = {'S': sha256(raw).hexdigest()}
    objects = {ledger['url_activity_key']['S']: raw}
    reference = (AUDIT.parent / 'aws-live/source/Team5-result/app.py') if dual_stack else (AUDIT / 'result-before.py')
    old, _ = load_app(monkeypatch, ledger, objects, source=reference)
    new, _ = load_app(monkeypatch, ledger, objects)
    old_body = json.loads(call(old, decision['request_id'])['body'])
    new_body = json.loads(call(new, decision['request_id'])['body'])
    assert old_body['status'] == new_body['status'] == 'COMPLETED'
    for key in ('verdict', 'route', 'judgment_status'):
        assert old_body[key] == new_body[key]
    for key in ('state', 'reason', 'scope', 'key', 'sha256'):
        assert old_body['url_activity'][key] == new_body['url_activity'][key]
    assert new_body['url_activity']['l1_address_observation'] == decision['l1_address_observation']
