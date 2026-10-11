"""Approved C01 selection, including absence, historical inputs and final wire guards."""
from copy import deepcopy
from datetime import timedelta
import json
from pathlib import Path

import pytest

from test_l2_certificate_age_measurement import capture_measurement, NOW, URL
from evidence_pipeline import build_context, build_record
from evidence_pipeline.context_inventory import restore
from evidence_pipeline.judgment_view_v2 import build_judgment_view_v2, validate_judgment_view_v2
from evidence_pipeline.l2_context import AGE_LABEL, TIME_LABEL, C01_MISSING, C01_FAILED
from evidence_pipeline.model_context import validate_model_context, VERSION as MODEL_CONTEXT_VERSION
from evidence_pipeline.records import digest


CASES = {'observed': {}, 'future_fraction': {'days': -0.25},
    'missing_start': {'missing_start': True}, 'invalid_start': {'invalid': True},
    'tls_timeout': {'tls_failure': True}, 'http_failure_tls_observed': {'http_failure': True},
    'different_scan_time': {'scan_finished_at': (NOW + timedelta(days=1)).isoformat()}}


@pytest.mark.parametrize('case', list(CASES))
def test_selected_c01_through_saved_record_and_messages(monkeypatch, case):
    artifacts = capture_measurement(monkeypatch, **CASES[case])
    raw, record, native, audit = (artifacts[key] for key in ('raw', 'record', 'native', 'audit'))
    assert audit['source_context']['l2_tls_source'] == raw['tls']
    assert record['signals'][0]['evidence'] == native['signals'][0]['evidence']
    source_c01 = next(x for x in audit['source_context']['observations'] if x['id'] == 'L2-C-01')
    assert source_c01['evidence'] == record['signals'][0]['evidence']
    view = artifacts['model-document']
    assert json.loads(artifacts['messages-request']['messages'][0]['content']) == view
    assert view['layer_boundaries']['model_context_version'] == MODEL_CONTEXT_VERSION
    rows = view['fact_units']
    assert not any(x['kind'] == 'check' and x['facts'].get('name') == 'certificate_age' for x in rows)
    measurements = [x for x in rows if x['kind'] == 'certificate_age']
    limits = [x['facts'] for x in rows if x['kind'] == 'certificate_age_limit']
    if case in {'observed', 'future_fraction', 'http_failure_tls_observed', 'different_scan_time'}:
        assert len(measurements) == 1 and not limits
        facts = measurements[0]['facts']
        assert facts[TIME_LABEL] == NOW.isoformat()
        assert facts[AGE_LABEL] == ('-1일 (유효기간 시작 전; 시간차를 24시간 단위로 내림한 값)' if case == 'future_fraction' else '15일')
        assert set(facts) == {AGE_LABEL, TIME_LABEL, 'certificate_ref'}
        cert = next(x for x in rows if x['id'] == facts['certificate_ref']['evidence_ref'])
        assert cert['facts']['inspected_host'] == raw['tls']['hostname']
    elif case == 'missing_start':
        assert not measurements and limits == [{'관측 한계': C01_MISSING}]
    elif case == 'invalid_start':
        assert not measurements and len(limits) == 1
        assert limits[0]['관측 한계'] == C01_FAILED
        assert 'ValueError' in limits[0]['이유']
    else:
        assert not measurements and not limits
        errors = [x for x in rows if x['kind'] == 'limitation'
                  and x['facts'].get('description', {}).get('code') == 'tls_timeout']
        assert len(errors) == 1
        assert 'affected_checks' not in errors[0]['facts']
        assert 'affected_signal_ids' not in errors[0]['facts']['occurrence'].get('no_entries_recorded', [])
        assert 'certificate_not_before_unavailable' not in json.dumps(view)
    if case == 'http_failure_tls_observed':
        assert record['coverage']['http_response_received'] is False
        assert raw['tls']['leaf_certificate']


@pytest.mark.parametrize('case', ['observed', 'tls_timeout', 'invalid_start'])
def test_c01_internal_row_cannot_reenter_final_gateway(monkeypatch, case):
    document = capture_measurement(monkeypatch, **CASES[case])['builder-document']
    wrapper = {'id': 'E999', 'kind': 'check', 'facts': {'layer': 'l2', 'name': 'certificate_age',
        'detected': True, 'evidence': {'fresh': True, 'age_days': 15}}}
    leaked = deepcopy(document)
    leaked['evidence'].append(wrapper)
    with pytest.raises(ValueError, match='c01_record_wrapper'):
        validate_model_context(leaked)
    view = build_judgment_view_v2(document)
    view['fact_units'].append(wrapper)
    ids = [row['id'] for row in view['fact_units']]
    view['source_accounting'].update(source_evidence_count=len(ids), fact_unit_count=len(ids),
        source_evidence_ids=ids, source_evidence_sha256=digest(view['fact_units']))
    with pytest.raises(ValueError, match='c01_record_wrapper'):
        validate_judgment_view_v2(view)


@pytest.mark.parametrize('field', ['not_before', 'fresh', 'measurement_state', 'assessment'])
def test_c01_compact_row_rejects_record_metadata(monkeypatch, field):
    document = capture_measurement(monkeypatch)['builder-document']
    row = next(x for x in document['evidence'] if x['kind'] == 'certificate_age')
    row['facts'][field] = 'unexpected'
    with pytest.raises(ValueError, match='invalid_c01_model_fields'):
        validate_model_context(document)


def test_c01_requires_reference_to_the_inspected_certificate(monkeypatch):
    document = capture_measurement(monkeypatch)['builder-document']
    row = next(x for x in document['evidence'] if x['kind'] == 'certificate_age')
    row['facts'].pop('certificate_ref')
    with pytest.raises(ValueError, match='invalid_c01_model_fields'):
        validate_model_context(document)


def test_legacy_c01_stays_in_record_and_audit_without_fabricated_measurement_time():
    raw = {'tls': {'hostname': 'example.com', 'leaf_certificate': {'not_before': '2026-09-03T12:14:57+00:00'}}}
    native = {'target': {'original_url': URL}, 'signals': [{'id': 'L2-C-01', 'name': 'certificate_age',
        'detected': True, 'evidence': {'age_days': 15, 'fresh': True}}]}
    record = build_record('l2', native, raw=raw, request_id='legacy-c01', attempt=1)
    before = deepcopy(record)
    audit = {}
    view = build_judgment_view_v2(build_context([record], {'l2': raw}, audit=audit))
    assert record == before and record['signals'][0]['evidence']['fresh'] is True
    assert audit['source_context']['observations'][0]['evidence']['fresh'] is True
    assert any(x['reason'] == 'legacy_c01_without_measurement_contract_retained_in_audit'
               for x in audit['model_omissions'])
    assert not any(x['kind'] == 'certificate_age' for x in view['fact_units'])
    assert 'fresh' not in json.dumps(view)


def test_saved_v3_c01_document_remains_readable(monkeypatch):
    document = capture_measurement(monkeypatch)['builder-document']
    document['model_context_version'] = 'decision-evidence-3'
    document['evidence'] = [x for x in document['evidence'] if x['kind'] != 'certificate_age']
    document['evidence'].append({'id': 'E999', 'kind': 'check', 'facts': {
        'layer': 'l2', 'name': 'certificate_age', 'evidence': {'age_days': 15, 'not_before': 'old'}}})
    validate_model_context(document)
    build_judgment_view_v2(document)


if __name__ == '__main__':
    output = Path(__file__).resolve().parents[2] / 'results' / 'c01-builder-20260928'
    for case, options in CASES.items():
        with pytest.MonkeyPatch.context() as patch:
            artifacts = capture_measurement(patch, **options)
        folder = output / case
        folder.mkdir(parents=True, exist_ok=True)
        for name, value in artifacts.items():
            (folder / (name + '.json')).write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
    print('Saved seven offline C01 cases from producer input through Messages.')
