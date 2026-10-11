"""Messages generation settings without changing Builder input or verdict rules."""
import io
import json
import sys
from types import SimpleNamespace

import pytest

from evidence_pipeline import aws_fast_result, aws_runtime
from evidence_pipeline.fast_judgment import PROMPT
from evidence_pipeline.gateway import AnthropicGateway, JudgmentServiceError


@pytest.mark.parametrize('model', ['claude-sonnet-5-5', 'claude-opus-5-5'])
def test_explicit_effort_preserves_wire_input_and_reads_text_after_thinking(model):
    from test_fast_result_contract import build_persisted, response_for

    event, store, output, _ = build_persisted('login')
    context = store.get(aws_fast_result.keys(event['job_id'], 1)['context'])
    requests = []
    def opener(request, **kwargs):
        # The live provider rejected urllib's default agent with Cloudflare 1010.
        # Identify this service explicitly without impersonating a browser.
        assert request.get_header('User-agent') == 'team5-url-analysis/1.0'
        assert request.get_header('Authorization') == 'Bearer offline-key'
        requests.append((json.loads(request.data), kwargs))
        response = {'model': model, 'stop_reason': 'end_turn', 'content': [
            {'type': 'thinking', 'thinking': '', 'signature': 'offline-signature'},
            {'type': 'text', 'text': json.dumps(response_for('login'), ensure_ascii=False)}]}
        return io.BytesIO(json.dumps(response, ensure_ascii=False).encode())

    gateway = AnthropicGateway('https://offline.example/router', 'offline-key', model,
                              timeout=120, max_tokens=8192, omit_temperature=True,
                              output_effort='high', opener=opener)
    result = aws_fast_result.run_judgment(
        {**event, 'context_key': output['final_key'], 'context_sha256': output['context_sha256']},
        store, lambda: gateway)
    assert result['judgment_status'] == 'accepted'
    assert len(requests) == 1
    sent, kwargs = requests[0]
    assert sent == {'model': model, 'max_tokens': 8192, 'system': PROMPT,
                    'messages': [{'role': 'user', 'content': context['model_body']}],
                    'output_config': {'effort': 'high'}}
    assert kwargs['timeout'] == 120
    public = store.get(result['fast_result_key'])
    assert public['judgment']['verdict'] == 'LIKELY_BENIGN'
    assert public['details'] == context['details']


def test_legacy_payload_has_unchanged_default_generation_fields():
    gateway = AnthropicGateway('https://offline.example', 'offline-key', 'existing-model')
    assert gateway._payload('system', 'user') == {
        'model': 'existing-model', 'max_tokens': 1600, 'temperature': 0,
        'system': 'system', 'messages': [{'role': 'user', 'content': 'user'}]}


@pytest.mark.parametrize('explicit', [False, True], ids=['legacy-env', 'claude55-env'])
def test_runtime_constructs_gateway_from_explicit_settings(monkeypatch, explicit):
    requested_secrets = []
    def secret(**kwargs):
        requested_secrets.append(kwargs['SecretId'])
        return {'SecretString': ' offline-test-key '}
    monkeypatch.setitem(sys.modules, 'boto3', SimpleNamespace(client=lambda service:
        SimpleNamespace(get_secret_value=secret) if service == 'secretsmanager' else object()))
    settings = {'EVIDENCE_ROLE': 'judgment', 'EVIDENCE_RESULT_CONTRACT': 'fast-result-1',
                'OUTPUT_BUCKET': aws_runtime.BUCKET, 'LLM_SECRET_ID': 'offline/secret',
                'ANTHROPIC_BASE_URL': 'https://offline.example/router',
                'JUDGMENT_MODEL': 'provider-exact-model-id', 'LLM_TIMEOUT_SECONDS': '120',
                'JUDGMENT_MAX_TOKENS': '8192'}
    for name, value in settings.items():
        monkeypatch.setenv(name, value)
    for name in ('ANTHROPIC_OMIT_TEMPERATURE', 'ANTHROPIC_OUTPUT_EFFORT'):
        monkeypatch.delenv(name, raising=False)
    if explicit:
        monkeypatch.setenv('ANTHROPIC_OMIT_TEMPERATURE', '1')
        monkeypatch.setenv('ANTHROPIC_OUTPUT_EFFORT', 'high')
    captured = []
    def run(event, store, factory):
        gateway = factory()
        captured.append(gateway)
        return gateway._payload('system', 'same user input')
    monkeypatch.setattr(aws_fast_result, 'run_judgment', run)
    payload = aws_runtime.handler({'job_id': 'offline'})
    assert payload['model'] == 'provider-exact-model-id'
    assert payload['max_tokens'] == 8192
    assert ('temperature' not in payload) is explicit
    assert payload.get('output_config') == ({'effort': 'high'} if explicit else None)
    assert captured[0].url == 'https://offline.example/router/v1/messages'
    assert captured[0].timeout == 120
    assert requested_secrets == ['offline/secret']


def test_thinking_budget_exhaustion_remains_service_failure():
    def opener(*args, **kwargs):
        return io.BytesIO(json.dumps({'stop_reason': 'max_tokens', 'content': [
            {'type': 'thinking', 'thinking': '', 'signature': 'offline'}]}).encode())
    gateway = AnthropicGateway('https://offline.example', 'offline-key', 'claude-sonnet-5-5',
                              omit_temperature=True, output_effort='high', opener=opener)
    with pytest.raises(JudgmentServiceError) as failure:
        gateway('system', 'user')
    assert failure.value.detail == {'kind': 'response_incomplete', 'stop_reason': 'max_tokens'}
    assert gateway.last_response['stop_reason'] == 'max_tokens'
