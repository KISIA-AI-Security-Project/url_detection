import io
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from time import sleep
from types import SimpleNamespace

import pytest

from evidence_pipeline import aws_clients, aws_fast_result, aws_runtime, performance
from evidence_pipeline.bedrock_gateway import BedrockAnthropicGateway
from evidence_pipeline.fast_judgment import PROMPT


@pytest.mark.parametrize('model', ['global.anthropic.claude-sonnet-5-5', 'global.anthropic.claude-opus-5-5'])
def test_bedrock_preserves_builder_and_actual_request_and_public_result(model, monkeypatch, capsys):
    from test_fast_result_contract import build_persisted, response_for
    event, store, output, _ = build_persisted('login')
    paths = aws_fast_result.keys(event['job_id'], 1)
    context = store.get(paths['context'])
    calls = []
    envelope = {'model': model.removeprefix('global.anthropic.'), 'stop_reason': 'end_turn',
                'content': [{'type': 'thinking', 'thinking': ''},
                            {'type': 'text', 'text': json.dumps(response_for('login'), ensure_ascii=False)}]}
    streams = []
    def invoke(**kwargs):
        calls.append(kwargs)
        streams.append(io.BytesIO(json.dumps(envelope, ensure_ascii=False).encode()))
        return {'body': streams[-1]}
    gateway = BedrockAnthropicGateway(model, client=SimpleNamespace(invoke_model=invoke))
    monkeypatch.setenv('EVIDENCE_TIMING', '1')
    with performance.invocation(event, None, 'judgment'):
        result = aws_fast_result.run_judgment(
            {**event, 'context_key': output['final_key'], 'context_sha256': output['context_sha256']},
            store, lambda: gateway)
    assert result['judgment_status'] == 'accepted'
    assert len(calls) == 1 and calls[0]['modelId'] == model
    assert calls[0]['body'] == gateway.last_request_body
    assert json.loads(calls[0]['body']) == store.get(paths['request']) == {
        'anthropic_version': 'bedrock-2023-05-31', 'max_tokens': 8192,
        'system': PROMPT, 'messages': [{'role': 'user', 'content': context['model_body']}],
        'output_config': {'effort': 'high'}}
    assert store.get(paths['response']) == envelope
    assert store.get(paths['result'])['details'] == context['details']
    assert store.get(paths['result'])['judgment']['verdict'] == response_for('login')['verdict']
    trace = json.loads(capsys.readouterr().out)
    names = [row['name'] for row in trace['spans']]
    assert names.count('judgment.provider_transport') == 1 and streams[0].closed
    assert all(row['success'] for row in trace['spans'])
    assert {'judgment.gateway_setup', 'judgment.request_prepare', 'judgment.response_validate',
            'judgment.link', 'judgment.public_build'} <= set(names)
    assert not any(b'provider_seconds' in raw or b'judgment.provider_transport' in raw
                   for raw in store.values.values())


@pytest.mark.parametrize('mode,expected', [('denied', 'failed'), ('truncated', 'invalid')])
def test_bedrock_failure_is_not_unknown_and_not_retried(mode, expected, monkeypatch, capsys):
    from test_fast_result_contract import build_persisted
    event, store, output, _ = build_persisted('login')
    calls = []
    class Denied(Exception):
        response = {'Error': {'Code': 'AccessDeniedException'}}
    def invoke(**kwargs):
        calls.append(kwargs)
        if mode == 'denied':
            raise Denied()
        return {'body': io.BytesIO(json.dumps({'stop_reason': 'max_tokens', 'content': []}).encode())}
    gateway = BedrockAnthropicGateway('global.anthropic.claude-sonnet-5-5',
                                     client=SimpleNamespace(invoke_model=invoke))
    monkeypatch.setenv('EVIDENCE_TIMING', '1')
    with performance.invocation(event, None, 'judgment'):
        result = aws_fast_result.run_judgment(
            {**event, 'context_key': output['final_key'], 'context_sha256': output['context_sha256']},
            store, lambda: gateway)
    assert result['judgment_status'] == expected and len(calls) == 1
    assert store.get(result['fast_result_key'])['judgment'] is None
    trace = json.loads(capsys.readouterr().out)
    transports = [row for row in trace['spans'] if row['name'] == 'judgment.provider_transport']
    assert len(transports) == 1 and transports[0]['success'] is (mode != 'denied')


def test_bedrock_client_reuse_keeps_request_state_and_configuration_separate(monkeypatch):
    calls = []
    def client(service, **kwargs):
        assert service == 'bedrock-runtime'
        sleep(0.01)  # Allow concurrent first callers to reach the cache while creation is in progress.
        value = object()
        calls.append((kwargs, value))
        return value
    monkeypatch.setitem(sys.modules, 'boto3', SimpleNamespace(client=client))
    monkeypatch.setitem(sys.modules, 'botocore.config', SimpleNamespace(Config=SimpleNamespace))
    monkeypatch.setattr(aws_clients, '_BEDROCK', {})
    barrier = Barrier(4)
    def first_call(_):
        barrier.wait()
        return BedrockAnthropicGateway('sonnet', region='ap-northeast-2')
    with ThreadPoolExecutor(max_workers=4) as pool:
        gateways = list(pool.map(first_call, range(4)))
    assert len(calls) == 1 and len({id(value.client) for value in gateways}) == 1
    gateways[0].last_request_body = b'previous request'
    other_model = BedrockAnthropicGateway('opus', region='ap-northeast-2', max_tokens=4096, output_effort=None)
    assert other_model.client is gateways[0].client and other_model.last_request_body is None
    assert other_model._payload('system', 'user')['max_tokens'] == 4096
    assert 'output_config' not in other_model._payload('system', 'user')
    different_timeout = BedrockAnthropicGateway('sonnet', region='ap-northeast-2', timeout=60)
    different_region = BedrockAnthropicGateway('sonnet', region='us-east-1')
    assert len(calls) == 3 and different_timeout.client is not other_model.client
    assert different_region.client is not other_model.client
    assert [(row['region_name'], row['config'].read_timeout) for row, _ in calls] == [
        ('ap-northeast-2', 120), ('ap-northeast-2', 60), ('us-east-1', 120)]
    assert all(row['config'].connect_timeout == 10 and
               row['config'].retries == {'total_max_attempts': 1} for row, _ in calls)


def test_runtime_bedrock_does_not_read_a_provider_api_key(monkeypatch):
    monkeypatch.setitem(sys.modules, 'boto3', SimpleNamespace(client=lambda service: object()
        if service == 's3' else pytest.fail('Bedrock must not read an API key')))
    import evidence_pipeline.bedrock_gateway as module
    settings = {'EVIDENCE_ROLE': 'judgment', 'EVIDENCE_RESULT_CONTRACT': 'fast-result-1',
                'OUTPUT_BUCKET': aws_runtime.BUCKET, 'JUDGMENT_PROVIDER': 'bedrock',
                'JUDGMENT_MODEL': 'global.anthropic.claude-sonnet-5-5',
                'ANTHROPIC_OUTPUT_EFFORT': 'high', 'AWS_REGION': 'ap-northeast-2'}
    for key, value in settings.items():
        monkeypatch.setenv(key, value)
    captured = []
    monkeypatch.setattr(module, 'BedrockAnthropicGateway', lambda model, **kwargs:
                        captured.append((model, kwargs)) or object())
    monkeypatch.setattr(aws_fast_result, 'run_judgment', lambda event, store, factory: factory())
    aws_runtime.handler({})
    assert captured[0][0] == settings['JUDGMENT_MODEL']
    assert captured[0][1]['region'] == 'ap-northeast-2'
