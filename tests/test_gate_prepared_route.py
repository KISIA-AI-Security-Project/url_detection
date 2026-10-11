"""Public submission keeps its ID/ledger/rescan contract when routing prepared work."""
import ast
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[1]
LEGACY = 'arn:aws:states:ap-northeast-2:998301375101:stateMachine:team5-orchestrator'
PREPARED = 'arn:aws:states:ap-northeast-2:998301375101:stateMachine:team5-itg-dns-parallel-20260916'


@pytest.fixture
def gate(monkeypatch):
    calls = []
    current = {'Item': {'status': {'S': 'JUDGED'}}}
    running = {'executions': []}
    def record(name, result):
        def run(**kw):
            calls.append((name, kw))
            return result
        return run
    ddb = SimpleNamespace(get_item=record('get', current), put_item=record('put', {}))
    sfn = SimpleNamespace(list_executions=record('list', running), start_execution=record('start', {}))
    monkeypatch.setitem(sys.modules, 'boto3', SimpleNamespace(client=lambda service: {'dynamodb': ddb, 'stepfunctions': sfn}[service]))
    monkeypatch.setenv('JOBS_TABLE', 'Team5-firstDB')
    monkeypatch.setenv('STATE_MACHINE_ARN', LEGACY)
    monkeypatch.setenv('PREPARED_STATE_MACHINE_ARN', PREPARED)
    monkeypatch.setenv('PREPARED_JOB_PREFIX', 'a50914')
    monkeypatch.setenv('EVIDENCE_TIMING', '1')
    spec = importlib.util.spec_from_file_location('prepared_gate_test', REPO/'deployment/gate/app.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, 'policy_gate', lambda url: (url, None))
    return module, calls, current, running


def submit(module, scan_id=None):
    body = {'url': 'https://example.com/'}
    if scan_id:
        body['scanId'] = scan_id
    return module.handler({'body': json.dumps(body)}, SimpleNamespace(aws_request_id='offline-gate'))


def test_new_submission_preserves_public_shape_and_durable_order(gate):
    module, calls, _, _ = gate
    result = submit(module)
    body = json.loads(result['body'])
    assert result['statusCode'] == 202
    assert set(body) == {'scanId', 'status', 'rescan', 'pollUrl'}
    assert module.ID_RE.fullmatch(body['scanId']) and body['scanId'].startswith('a50914')
    assert body == {'scanId': body['scanId'], 'status': 'PENDING', 'rescan': False,
                    'pollUrl': '/analyses/' + body['scanId']}
    assert [name for name, _ in calls] == ['put', 'start']
    item = calls[0][1]['Item']
    assert item['result_contract_version'] == {'S': 'fast-result-1'}
    assert item['judgment_status'] == {'S': 'pending'}
    assert calls[0][1]['ConditionExpression'] == 'attribute_not_exists(job_id)'
    assert calls[1][1]['stateMachineArn'] == PREPARED
    assert json.loads(calls[1][1]['input']) == {'job_id': body['scanId'], 'url': 'https://example.com/'}


@pytest.mark.parametrize('job,expected', [('1' * 32, LEGACY), ('a50914' + '1' * 26, PREPARED)])
def test_existing_rescan_uses_its_pipeline_without_overwriting_ledger(gate, job, expected):
    module, calls, _, _ = gate
    result = submit(module, job)
    assert result['statusCode'] == 202
    assert json.loads(result['body'])['scanId'] == job
    assert [name for name, _ in calls] == ['get', 'list', 'start']
    assert calls[1][1]['stateMachineArn'] == expected
    assert calls[2][1]['stateMachineArn'] == expected


def test_running_rescan_is_not_started(gate):
    module, calls, _, running = gate
    job = 'a50914' + '2' * 26
    running['executions'].append({'name': 'scan-' + job})
    assert submit(module, job)['statusCode'] == 409
    assert [name for name, _ in calls] == ['get', 'list']


def test_missing_rescan_stays_not_found(gate):
    module, calls, current, _ = gate
    current.clear()
    assert submit(module, '1' * 32)['statusCode'] == 404
    assert [name for name, _ in calls] == ['get']


def test_disabled_prepared_route_preserves_legacy_submission(gate, monkeypatch):
    module, calls, _, _ = gate
    monkeypatch.setattr(module, 'PREPARED_SM_ARN', '')
    monkeypatch.setattr(module, 'PREPARED_PREFIX', '')
    assert submit(module)['statusCode'] == 202
    assert 'result_contract_version' not in calls[0][1]['Item']
    assert calls[1][1]['stateMachineArn'] == LEGACY


def test_policy_rejection_still_has_no_aws_side_effect(gate, monkeypatch):
    module, calls, _, _ = gate
    monkeypatch.setattr(module, 'policy_gate', lambda url: (None, 'blocked'))
    assert submit(module)['statusCode'] == 400
    assert not calls


def test_deployed_policy_function_is_unchanged():
    baseline = REPO.parents[1]/'remediation-20261005/performance-round4/aws-live/source/Team5-gate/app.py'
    def function(path):
        tree = ast.parse(path.read_text(encoding='utf-8'))
        return ast.dump(next(x for x in tree.body if isinstance(x, ast.FunctionDef) and x.name == 'policy_gate'))
    assert function(baseline) == function(REPO/'deployment/gate/app.py')
