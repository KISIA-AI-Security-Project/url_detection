"""Active provider contract and stored public/deep compatibility, not accuracy."""
from copy import deepcopy

import pytest

from evidence_pipeline.fast_judgment import validate_response
from evidence_pipeline.fast_public import validate_public_result
from evidence_pipeline.aws_fast_result import load_deep_input
from test_fast_result_contract import build_persisted, call, response_for


def likelihood_response(direction):
    value = response_for('login')
    value['verdict'] = direction
    value['decision_notes']['provisional_assessment'] = {
        'direction_basis': '통제 입력의 방향 근거.',
        'consequential_uncertainty': '통제 입력의 중요한 미확정 관계.'}
    return value


@pytest.mark.parametrize('direction', ['LIKELY_BENIGN', 'LIKELY_MALICIOUS'])
def test_likelihood_notes_reach_private_deep_input_without_public_leak(direction):
    event, store, output, _ = build_persisted('login')
    value = likelihood_response(direction)
    result, calls, job = call(event, store, output, value)
    public = store.get(result['fast_result_key'])
    assert len(calls) == 1 and public['judgment']['verdict'] == direction
    assert 'decision_notes' not in public['judgment']
    deep = load_deep_input({**event, 'context_revision': public['context_revision'],
                            'result_revision': public['result_revision']}, store)
    assert deep['previous_judgment'] == value


@pytest.mark.parametrize('bad', ['missing', 'empty', 'wrong_type'])
def test_likelihood_requires_actual_nonempty_provisional_fields(bad):
    value = likelihood_response('LIKELY_BENIGN')
    if bad == 'missing':
        del value['decision_notes']['provisional_assessment']['consequential_uncertainty']
    elif bad == 'empty':
        value['decision_notes']['provisional_assessment']['consequential_uncertainty'] = ' '
    else:
        value['decision_notes']['provisional_assessment'] = []
    with pytest.raises(ValueError):
        validate_response(value)


def test_new_provider_cannot_emit_legacy_suspicious_or_use_likelihood_notes_for_benign():
    legacy = response_for('document-link')
    legacy['verdict'] = 'SUSPICIOUS'
    with pytest.raises(ValueError, match='invalid_verdict'):
        validate_response(legacy)
    value = likelihood_response('LIKELY_BENIGN')
    value['verdict'] = 'BENIGN'
    with pytest.raises(ValueError, match='unexpected_provisional_assessment'):
        validate_response(value)


def test_old_public_history_is_readable_without_reclassification():
    event, store, output, _ = build_persisted('login')
    result, _, _ = call(event, store, output, response_for('login'))
    saved = store.get(result['fast_result_key'])
    for verdict in ('BENIGN', 'LIKELY_BENIGN', 'LIKELY_MALICIOUS', 'MALICIOUS', 'UNKNOWN', 'SUSPICIOUS'):
        original = deepcopy(saved)
        original['judgment']['verdict'] = verdict
        assert validate_public_result(original, job_id=event['job_id'], attempt=1) == original
