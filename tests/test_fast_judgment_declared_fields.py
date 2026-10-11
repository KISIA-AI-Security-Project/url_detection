"""Unused provider extensions never replace required judgment contents."""
from copy import deepcopy

import pytest

from evidence_pipeline.fast_judgment import validate_response
from test_fast_result_contract import response_for


def add_extensions(value):
    if isinstance(value, dict):
        for child in list(value.values()):
            add_extensions(child)
        value['unused_provider_extension'] = {'anything': [None, 1, False]}
    elif isinstance(value, list):
        for child in value:
            add_extensions(child)


@pytest.mark.parametrize('case', ['login', 'document-link', 'credential-deception', 'insufficient'])
def test_select_declared_fields_at_every_depth_without_mutating_raw(case):
    expected = response_for(case)
    expected['decision_notes']['follow_up_questions'] = [
        {'question': '확인할 내용', 'why_it_could_change_the_decision': '판단을 바꿀 관계'}]
    raw = deepcopy(expected)
    add_extensions(raw)
    original = deepcopy(raw)
    assert validate_response(raw) == expected
    assert raw == original


@pytest.mark.parametrize('change', ['missing', 'wrong_type', 'empty', 'verdict', 'conditional', 'misplaced'])
def test_extensions_cannot_supply_or_repair_required_values(change):
    raw = response_for('login')
    if change == 'missing':
        del raw['reasons'][0]['related_items']
    elif change == 'wrong_type':
        raw['reasons'][0]['related_items'] = {}
    elif change == 'empty':
        raw['reasons'][0]['text'] = ' '
    elif change == 'verdict':
        raw['verdict'] = 'SAFE'
    elif change == 'conditional':
        raw['decision_notes']['provisional_assessment'] = {}
    else:
        item = raw['reasons'][0]['related_items'][0]
        raw['reasons'][0]['item_label'] = item.pop('item_label')
    add_extensions(raw)
    original = deepcopy(raw)
    with pytest.raises(ValueError):
        validate_response(raw)
    assert raw == original
