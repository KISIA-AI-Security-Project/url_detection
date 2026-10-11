"""Offline Result validation of the exact L0 Messages body and saved audit view."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import runpy
import sys
import types

import pytest

from test_l0_context_wire import capture_l0_request


@pytest.fixture(scope='module')
def saved_l0_request():
    return capture_l0_request(include_store=True)


@pytest.fixture
def result_validator(monkeypatch):
    # Loading the Result module creates clients. This direct validator test must
    # never reach AWS; the placeholder clients expose no service operations.
    boto3 = types.ModuleType('boto3')
    boto3.client = lambda name: object()
    monkeypatch.setitem(sys.modules, 'boto3', boto3)
    monkeypatch.setenv('JOBS_TABLE', 'offline-l0-consumer-test')
    monkeypatch.setenv('EVIDENCE_BUCKET', 'offline-l0-consumer-test')
    app = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'deployment/result/app.py'))
    return app['_valid_v2_result']


def consumer_inputs(artifacts):
    store = artifacts['_store']
    judgment = store.get(artifacts['mock_adapter_result']['judgment_key'])
    prefix = judgment['view_key'].rsplit('/', 1)[0] + '/'
    return {
        'scan_id': judgment['job_id'],
        'attempt': judgment['attempt'],
        'url': judgment['input_url'],
        'verdict': judgment['verdict'],
        'judgment': judgment,
        'final_doc': store.get(judgment['context_key']),
        'view': store.get(judgment['view_key']),
        'selection': store.get(prefix + 'selection.json'),
        'review': store.get(prefix + 'review.json'),
        'processing': store.get(prefix + 'processing.json'),
        'saved_consumer': store.get(prefix + 'consumer.json'),
        'request_bytes': store.values[prefix + 'request.json'],
        'response': store.get(prefix + 'response.json'),
        'request_claim': store.get(prefix + 'request-claim.json'),
        'transport': store.get(prefix + 'transport.json'),
    }


def rebind_request_bytes(inputs, data):
    """Keep every request hash checked by Result consistent with the new bytes."""
    inputs['request_bytes'] = data
    request_sha = sha256(data).hexdigest()
    for artifact in ('judgment', 'request_claim', 'transport'):
        inputs[artifact]['request_sha256'] = request_sha
    assert {inputs[name]['request_sha256'] for name in (
        'judgment', 'request_claim', 'transport')} == {sha256(inputs['request_bytes']).hexdigest()}


def test_result_accepts_captured_l0_request_under_existing_full_view_contract(
        saved_l0_request, result_validator):
    inputs = consumer_inputs(saved_l0_request)
    request = json.loads(inputs['request_bytes'])
    model_document = json.loads(request['messages'][0]['content'])
    assert model_document == saved_l0_request['final_model_document']
    assert model_document == inputs['view']
    assert 'source_accounting' in inputs['view']
    assert model_document['fact_units'] == inputs['view']['fact_units']
    assert result_validator(**inputs) is True

    # Byte changes alone remain valid after rebinding all request hashes. The
    # tampering tests below therefore exercise the selected-document contract.
    reformatted = json.dumps(request, ensure_ascii=False, indent=2).encode()
    assert reformatted != inputs['request_bytes']
    rebind_request_bytes(inputs, reformatted)
    assert result_validator(**inputs) is True


@pytest.mark.parametrize('change', [
    'guidance_removed', 'unselected_fact_removed', 'l0_metadata_reintroduced',
])
def test_result_rejects_changed_l0_model_document_even_with_all_request_hashes_rebound(
        saved_l0_request, result_validator, change):
    inputs = consumer_inputs(saved_l0_request)
    assert result_validator(**inputs) is True
    audit_view = deepcopy(inputs['view'])
    request = json.loads(inputs['request_bytes'])
    model_document = json.loads(request['messages'][0]['content'])
    if change == 'guidance_removed':
        del model_document['layer_boundaries']['reading_guide']['l0']['추가 판단 안내']['DGA_패턴']
    elif change == 'unselected_fact_removed':
        selected_ids = {value for key, value in inputs['selection'].items() if '_fact_id_' in key}
        removed = next(row for row in model_document['fact_units']
                       if row['kind'] == 'url_observation' and row['id'] not in selected_ids)
        model_document['fact_units'].remove(removed)
    else:
        observation = next(row for row in model_document['fact_units']
                           if row['kind'] == 'url_observation')
        observation['facts']['관찰'][0]['errors'] = [{'code': 'must-not-reenter-l0-model'}]
    request['messages'][0]['content'] = json.dumps(
        model_document, ensure_ascii=False, separators=(',', ':'))
    forged_bytes = json.dumps(request, ensure_ascii=False, separators=(',', ':')).encode()
    assert forged_bytes != inputs['request_bytes']
    rebind_request_bytes(inputs, forged_bytes)

    # Original facts, their audit accounting, and the response selection stay
    # valid. A consistent hash chain must not authorize a different model input.
    assert inputs['view'] == audit_view
    assert result_validator(**inputs) is False
