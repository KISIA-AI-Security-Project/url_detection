"""Exercise the v2 adapter with the preserved active AWS URL evidence."""
from copy import deepcopy
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import runpy
import sys
import types

import pytest

from evidence_pipeline.aws_judgment_v2 import JudgmentV2Gateway, judgment_v2, LEGACY_STRUCTURED_PROMPT
from evidence_pipeline.judgment_contract_v2 import anthropic_output_config_v2
from evidence_pipeline.aws_runtime import PipelineServiceError
from evidence_pipeline.judgment_view_v2 import build_judgment_view_v2
from evidence_pipeline.records import digest
from deployment.build_judgment_v2_candidate import patch_definition


FIXTURE = (Path(__file__).resolve().parents[3] / 'dns-inactivity-20260916' /
           'aws-validation-v5/dual-dns-v5-validation/active-v5-direct.json')
DEFINITION = (Path(__file__).resolve().parents[3] / 'dns-inactivity-20260916' /
              'dual-dns-failure-patch-v2/definition-v5.json')


class MemoryStore:
    def __init__(self, data):
        self.data = deepcopy(data)
        self.writes = []

    def get(self, key, optional=False):
        if key not in self.data and not optional:
            raise KeyError(key)
        return self.data.get(key)

    def put(self, key, value, exclusive=False):
        if exclusive and key in self.data:
            raise AssertionError('immutable artifact overwritten')
        self.data[key] = deepcopy(value)
        self.writes.append(key)

    def put_bytes(self, key, value, exclusive=False):
        self.put(key, value, exclusive)


def source():
    value = json.loads(FIXTURE.read_text(encoding='utf-8'))
    final = value['artifacts']['final']['value']
    decision = value['artifacts']['url_activity']['value']
    key = value['context']['final_key']
    store = MemoryStore({key: final, final['url_activity_key']: decision})
    event = {'job_id': final['job_id'], 'attempt': final['attempt'],
             'url': final['input_url'], 'context_key': key,
             'context_sha256': final['model_context_sha256']}
    return store, event


def provider(selection, calls, raw_body=None):
    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, size):
            if raw_body is not None:
                return raw_body
            return json.dumps({'stop_reason': 'end_turn', 'content': [
                {'type': 'text', 'text': json.dumps(selection, ensure_ascii=False)}]
            }, ensure_ascii=False).encode()

    def factory(view):
        def open_request(request, **kwargs):
            calls.append(json.loads(request.data))
            assert kwargs['timeout'] == 5
            assert request.get_header('User-agent') == 'team5-judgment-lambda/1.0'
            return Response()
        return JudgmentV2Gateway('https://example.net', 'test-key', 'test-model',
                                 view=view, timeout=5, max_tokens=500, opener=open_request)
    return factory


@pytest.mark.skipif(not FIXTURE.is_file(), reason='preserved AWS evidence unavailable')
def test_active_actual_context_accepted_and_replay_does_not_recall_provider():
    store, event = source()
    calls = []
    selection = {'verdict': 'UNKNOWN', 'interpretation_text': '이번 테스트에는 판정 근거가 부족하다.',
                 'basis_fact_id_1': 'E1'}
    result = judgment_v2(event, store, provider(selection, calls))
    assert result['judgment_status'] == 'completed'
    assert len(calls) == 1
    assert 'output_config' not in calls[0]
    view = json.loads(calls[0]['messages'][0]['content'])
    assert len(view['fact_units']) == 68
    assert view['source_accounting']['source_evidence_count'] == 68
    assert view['omitted_evidence'] == []
    assert view['url_activity_observation'] == store.data[event['context_key']]['model_context']['url_activity_observation']
    assert [Path(key).name for key in store.writes] == [
        'request-claim.json', 'view.json', 'request.json', 'response-capture.json',
        'transport.json', 'response.json', 'selection.json',
        'review.json', 'processing.json', 'consumer.json', '1.json']
    assert judgment_v2(event, store, provider(selection, calls)) == result
    assert len(calls) == 1


@pytest.mark.skipif(not FIXTURE.is_file(), reason='preserved AWS evidence unavailable')
@pytest.mark.parametrize('changes', [
    {'basis_fact_id_1': 'E999999'},
    {'basis_fact_id_2': 'E1'},
    {'verdict': 'SAFE'},
    {'unexpected_field': True},
])
def test_plain_json_response_still_rejects_invalid_contract_before_publication(changes):
    store, event = source()
    selection = {'verdict': 'UNKNOWN', 'interpretation_text': '근거가 부족하다.',
                 'basis_fact_id_1': 'E1', **changes}
    with pytest.raises(ValueError):
        judgment_v2(event, store, provider(selection, []))
    assert f"judgments/{event['job_id']}/{event['attempt']}.json" not in store.data
    assert not any(key.endswith('/consumer.json') for key in store.writes)


@pytest.mark.skipif(not FIXTURE.is_file(), reason='preserved AWS evidence unavailable')
def test_plain_json_accepts_json_fence_without_relaxing_reference_validation():
    store, event = source()
    selection = {'verdict': 'UNKNOWN', 'interpretation_text': '근거가 부족하다.',
                 'basis_fact_id_1': 'E1'}
    raw = json.dumps({'stop_reason': 'end_turn', 'content': [{
        'type': 'text', 'text': '```json\n' + json.dumps(selection) + '\n```'}]}).encode()
    result = judgment_v2(event, store, provider(selection, [], raw_body=raw))
    assert result['judgment_status'] == 'completed'


@pytest.mark.skipif(not FIXTURE.is_file(), reason='preserved AWS evidence unavailable')
def test_builder_activity_observation_is_not_lost_from_provider_view():
    store, event = source()
    context = store.data[event['context_key']]['model_context']
    original = build_judgment_view_v2(context)
    changed = deepcopy(context)
    changed['url_activity_observation']['state'] = 'DNS_UNKNOWN'
    other = build_judgment_view_v2(changed)
    assert original['fact_units'] == other['fact_units']
    assert original['url_activity_observation'] != other['url_activity_observation']
    assert original['source_accounting']['source_activity_sha256'] != other['source_accounting']['source_activity_sha256']


@pytest.mark.skipif(not FIXTURE.is_file(), reason='preserved AWS evidence unavailable')
def test_unlinked_credential_transfer_is_preserved_but_not_published():
    store, event = source()
    calls = []
    selection = {'verdict': 'SUSPICIOUS',
                 'interpretation_text': '비밀번호가 외부로 전송되었다.',
                 'basis_fact_id_1': 'E1'}
    with pytest.raises(PipelineServiceError, match='credential_transfer_claim_requires_linked_basis'):
        judgment_v2(event, store, provider(selection, calls))
    prefix = f"judgments/{event['job_id']}/{event['attempt']}/v2/"
    assert len(calls) == 1
    assert store.data[prefix + 'selection.json'] == selection
    assert store.data[prefix + 'processing.json']['status'] == 'rejected'
    assert prefix + 'consumer.json' not in store.data
    assert f"judgments/{event['job_id']}/{event['attempt']}.json" not in store.data
    with pytest.raises(PipelineServiceError, match='prior_judgment_attempt_incomplete'):
        judgment_v2(event, store, provider(selection, calls))
    assert len(calls) == 1


@pytest.mark.skipif(not FIXTURE.is_file(), reason='preserved AWS evidence unavailable')
def test_malformed_provider_body_is_retained_without_a_verdict():
    store, event = source()
    calls = []
    with pytest.raises(Exception, match='response_format_invalid'):
        judgment_v2(event, store, provider({}, calls, raw_body=b'<bad-json>'))
    prefix = f"judgments/{event['job_id']}/{event['attempt']}/v2/"
    capture = store.data[prefix + 'response-capture.json']
    assert capture['body_utf8_redacted'] == '<bad-json>'
    assert capture['parse_state'] == 'invalid_json'
    assert store.data[prefix + 'transport.json']['http_status'] == 200
    assert store.data[prefix + 'failure.json']['kind'] == 'response_format_invalid'
    assert prefix + 'consumer.json' not in store.data
    assert f"judgments/{event['job_id']}/{event['attempt']}.json" not in store.data
    assert len(calls) == 1


@pytest.mark.skipif(not FIXTURE.is_file(), reason='preserved AWS evidence unavailable')
def test_header_wait_timeout_is_exposed_as_a_specific_failure():
    store, event = source()

    def factory(view):
        def open_request(request, **kwargs):
            gateway.phase_trace.enter('response_headers')
            gateway.phase_trace.request_bytes_written = len(request.data)
            error = TimeoutError('simulated header wait')
            gateway.phase_trace.failed(error)
            raise error

        gateway = JudgmentV2Gateway('https://example.net', 'test-key', 'test-model',
                                    view=view, timeout=5, opener=open_request)
        return gateway

    with pytest.raises(Exception, match='model_api_response_headers_timeout'):
        judgment_v2(event, store, factory)
    prefix = f"judgments/{event['job_id']}/{event['attempt']}/v2/"
    failure = store.data[prefix + 'failure.json']
    assert failure['error_code'] == 'model_api_response_headers_timeout'
    assert failure['original_error_code'] == 'request_timeout'
    assert failure['failure_phase'] == 'response_headers'
    assert failure['exception_type'] == 'TimeoutError'
    assert failure['request_bytes_written'] > 0
    assert failure['response_headers_received'] is False
    assert prefix + 'transport.json' in store.data
    assert f"judgments/{event['job_id']}/{event['attempt']}.json" not in store.data


@pytest.mark.skipif(not FIXTURE.is_file(), reason='preserved AWS evidence unavailable')
def test_dns_skip_prevents_provider_invocation():
    store, event = source()
    decision = store.data[store.data[event['context_key']]['url_activity_key']]
    decision['can_skip_judgment'] = True
    final = store.data[event['context_key']]
    final['url_activity_sha256'] = digest(decision)
    calls = []
    with pytest.raises(PipelineServiceError, match='judgment_forbidden_by_dns_activity'):
        judgment_v2(event, store, provider({}, calls))
    assert calls == []
    assert store.writes == []


@pytest.mark.skipif(not FIXTURE.is_file(), reason='preserved AWS evidence unavailable')
@pytest.mark.parametrize('protocol', ['plain', 'legacy'])
def test_result_candidate_requires_matching_accepted_v2_artifact(monkeypatch, protocol):
    store, event = source()
    factory = provider({
        'verdict': 'UNKNOWN', 'interpretation_text': '이번 테스트에는 판정 근거가 부족하다.',
        'basis_fact_id_1': 'E1'}, [])
    if protocol == 'legacy':
        plain_factory = factory
        def factory(view):
            gateway = plain_factory(view)
            make_payload = gateway._payload
            def legacy_payload(system, user):
                payload = make_payload(LEGACY_STRUCTURED_PROMPT, user)
                payload['output_config'] = anthropic_output_config_v2(view)
                return payload
            gateway._payload = legacy_payload
            return gateway
    result = judgment_v2(event, store, factory)
    item = {'job_id': {'S': event['job_id']}, 'url': {'S': event['url']},
            'attempt': {'N': '1'}, 'status': {'S': 'JUDGED'},
            'final_verdict': {'S': 'UNKNOWN'},
            'final_key': {'S': event['context_key']},
            'judgment_key': {'S': result['judgment_key']},
            'judgment_contract_version': {'S': 'fact-interpretation-selection-2'}}
    class DDB:
        def get_item(self, **kwargs):
            return {'Item': item}
    class S3:
        def get_object(self, **kwargs):
            value = store.data[kwargs['Key']]
            body = value if isinstance(value, bytes) else json.dumps(
                value, ensure_ascii=False,
                sort_keys=kwargs['Key'].endswith('/view.json'),
                separators=(',', ':')).encode()
            return {'Body': io.BytesIO(body)}
    boto3 = types.ModuleType('boto3')
    boto3.client = lambda name: DDB() if name == 'dynamodb' else S3()
    monkeypatch.setitem(sys.modules, 'boto3', boto3)
    monkeypatch.setenv('JOBS_TABLE', 'Team5-firstDB')
    monkeypatch.setenv('EVIDENCE_BUCKET', 'team5-evidence-998301375101-ap-northeast-2-an')
    app = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'deployment/result/app.py'))
    request = {'pathParameters': {'scanId': event['job_id']}}
    accepted = json.loads(app['handler'](request, None)['body'])
    assert accepted['status'] == 'COMPLETED'
    assert accepted['verdict'] == 'UNKNOWN'
    original = deepcopy(store.data)
    store.data[result['judgment_key']]['processing_status'] = 'rejected'
    blocked = json.loads(app['handler'](request, None)['body'])
    assert blocked['status'] == 'FAILED'
    assert blocked['verdict'] == 'UNDETERMINED'
    store.data[result['judgment_key']]['processing_status'] = 'accepted'
    store.data[result['judgment_key']]['context_sha256'] = '0' * 64
    assert json.loads(app['handler'](request, None)['body'])['status'] == 'FAILED'
    store.data[result['judgment_key']]['context_sha256'] = event['context_sha256']
    store.data[result['judgment_key']]['consumer']['interpretation']['basis_fact_ids'] = ['NO_SUCH_FACT']
    assert json.loads(app['handler'](request, None)['body'])['status'] == 'FAILED'
    store.data = deepcopy(original)
    prefix = f"judgments/{event['job_id']}/{event['attempt']}/v2/"
    view = store.data[prefix + 'view.json']
    view['fact_units'][-1]['facts']['forged_unselected_marker'] = 'forged'
    view['source_accounting']['source_evidence_sha256'] = digest(view['fact_units'])
    store.data[result['judgment_key']]['view_sha256'] = digest(view)
    store.data[result['judgment_key']]['source_evidence_sha256'] = digest(view['fact_units'])
    assert json.loads(app['handler'](request, None)['body'])['status'] == 'FAILED'
    store.data = deepcopy(original)
    text = '비밀번호가 외부로 전송되었다.'
    store.data[prefix + 'selection.json']['interpretation_text'] = text
    store.data[prefix + 'consumer.json']['interpretation']['text'] = text
    store.data[prefix + 'consumer.json']['provider_selection']['interpretation_text'] = text
    store.data[result['judgment_key']]['consumer'] = deepcopy(store.data[prefix + 'consumer.json'])
    assert json.loads(app['handler'](request, None)['body'])['status'] == 'FAILED'
    store.data = deepcopy(original)
    forged_request = json.loads(store.data[prefix + 'request.json'])
    forged_request['messages'][0]['content'] = '{}'
    data = json.dumps(forged_request, ensure_ascii=False, separators=(',', ':')).encode()
    store.data[prefix + 'request.json'] = data
    store.data[result['judgment_key']]['request_sha256'] = sha256(data).hexdigest()
    assert json.loads(app['handler'](request, None)['body'])['status'] == 'FAILED'
    store.data = deepcopy(original)
    forged_request = json.loads(store.data[prefix + 'request.json'])
    forged_request['max_tokens'] = 1
    data = json.dumps(forged_request, ensure_ascii=False, separators=(',', ':')).encode()
    store.data[prefix + 'request.json'] = data
    store.data[result['judgment_key']]['request_sha256'] = sha256(data).hexdigest()
    assert json.loads(app['handler'](request, None)['body'])['status'] == 'FAILED'
    store.data = deepcopy(original)
    forged_request = json.loads(store.data[prefix + 'request.json'])
    forged_request['top_p'] = 0.01
    data = json.dumps(forged_request, ensure_ascii=False, separators=(',', ':')).encode()
    store.data[prefix + 'request.json'] = data
    store.data[result['judgment_key']]['request_sha256'] = sha256(data).hexdigest()
    assert json.loads(app['handler'](request, None)['body'])['status'] == 'FAILED'


@pytest.mark.skipif(not DEFINITION.is_file(), reason='preserved AWS definition unavailable')
def test_isolated_definition_resets_v2_tag_on_next_attempt():
    old = json.loads(DEFINITION.read_text(encoding='utf-8'))
    arn = 'arn:aws:lambda:ap-northeast-2:998301375101:function:team5-itg-judgment-20260914:12'
    new = patch_definition(old, arn)
    assert [key for key in old['States'] if old['States'][key] != new['States'][key]] == [
        'AllocAttempt', 'JudgmentTask', 'MarkJudged']
    assert 'judgment_contract_version' in new['States']['AllocAttempt']['Parameters']['UpdateExpression']
    assert new['States']['JudgmentTask']['Parameters']['FunctionName'] == arn
    assert new['States']['MarkJudged']['Parameters']['ExpressionAttributeValues'][':jcv'] == {
        'S': 'fact-interpretation-selection-2'}
