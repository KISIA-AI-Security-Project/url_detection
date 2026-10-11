"""Approved C02 selection from native input through saved record and Messages."""
from copy import deepcopy
from datetime import timedelta
import json
from pathlib import Path
import socket

import pytest

from test_l2_certificate_age_measurement import NOW, FixedClock, StoredJSON
from test_l2_h09_context import capture_messages
from l2_scanner import scanner
from l2_scanner.analyzers.certificate import certificate_age, certificate_validity, ct_first_seen
from l2_scanner.collectors import certificate_collector
from evidence_pipeline import build_context, build_record
from evidence_pipeline.aws_runtime import persist_layer, load_existing_layer
from evidence_pipeline.context_inventory import restore
from evidence_pipeline.judgment_view_v2 import build_judgment_view_v2, validate_judgment_view_v2
from evidence_pipeline.l2_context import VALIDITY_LABEL, VALIDITY_TEXT, C02_FAILED, C02_UNRECORDED, AGE_LABEL, TIME_LABEL, TLS_MISSING
from evidence_pipeline.model_context import validate_model_context, VERSION
from evidence_pipeline.records import digest


CASES = ('valid', 'expired', 'future', 'at_start', 'at_end', 'tls_timeout', 'no_https',
         'missing_end', 'invalid_end', 'missing_end_key', 'absent_certificate',
         'http_failure', 'different_clocks', 'final_http')


def capture_validity(monkeypatch, case='valid', *, include_c01=True):
    def no_network(*args, **kwargs):
        raise AssertionError('C02 verification must stay offline')
    monkeypatch.setattr(socket, 'create_connection', no_network)
    monkeypatch.setattr(socket, 'getaddrinfo', no_network)
    for analyzer in (certificate_age, certificate_validity, ct_first_seen):
        monkeypatch.setattr(analyzer, 'datetime', FixedClock)
    start, end = NOW - timedelta(days=15), NOW + timedelta(days=60)
    if case == 'expired': end = NOW - timedelta(seconds=1)
    if case == 'future': start = NOW + timedelta(seconds=1)
    if case in {'at_start', 'different_clocks'}: start = NOW
    if case == 'at_end': end = NOW
    leaf = {'not_before': start.isoformat(), 'not_after': end.isoformat(),
            'fingerprint': 'offline', 'sct_timestamps': []}
    if case == 'missing_end': leaf['not_after'] = None
    if case == 'invalid_end': leaf['not_after'] = 'invalid-date'
    if case == 'missing_end_key': leaf.pop('not_after')
    if case == 'absent_certificate': leaf = None
    if case == 'different_clocks':
        class EarlierClock(FixedClock):
            @classmethod
            def now(cls, tz=None):
                return super().now(tz) - timedelta(seconds=1)
        monkeypatch.setattr(certificate_age, 'datetime', EarlierClock)
    if case == 'tls_timeout':
        def failed_handshake(*args, **kwargs):
            raise TimeoutError('offline TLS timeout')
        monkeypatch.setattr(certificate_collector, '_handshake', failed_handshake)
    elif case != 'no_https':
        def collected(hostname, port):
            return {'hostname': hostname, 'tls_version': 'TLSv1.3', 'leaf_certificate': deepcopy(leaf),
                    'certificate_chain': [], 'chain_valid': None, 'chain_error': None, 'errors': []}
        monkeypatch.setattr(scanner, 'collect_certificate', collected)
    monkeypatch.setattr(scanner, 'collect_ct', lambda *args: {
        'first_seen': (NOW - timedelta(days=45)).isoformat(), 'source': 'offline_fixture',
        'sct_count': 0, 'log_entries': 1, 'errors': []})
    monkeypatch.setattr(scanner, 'etld1', lambda value: 'example.com')
    # Deliberately different from the analyzer time, so the Builder cannot use it.
    monkeypatch.setattr(scanner, '_now_iso', lambda: (NOW + timedelta(minutes=1)).isoformat())
    monkeypatch.setattr(scanner, 'HEADER_ANALYZERS', [])
    monkeypatch.setattr(scanner, 'CERTIFICATE_ANALYZERS',
                        [certificate_age, certificate_validity] if include_c01 else [certificate_validity])
    monkeypatch.setattr(scanner, 'CERTIFICATE_ANALYZERS_EXTENDED', [])
    url = 'http://example.com/' if case == 'no_https' else 'https://example.com/'
    http = {'original_url': url, 'final_url': url, 'current_url': url, 'status_code': 200,
            'redirect_chain': [], 'headers': {}, 'response_body': {'body_complete': True},
            'download': {}, 'errors': []}
    if case == 'http_failure':
        http.update(final_url=None, status_code=None,
                    errors=[{'stage': 'http', 'code': 'connection_failed', 'error': 'offline HTTP failure'}])
    elif case == 'final_http':
        http.update(final_url='http://other.example.com/', current_url='http://other.example.com/')
    native = scanner._scan_collected(http, NOW.isoformat())
    before = deepcopy(native)
    store = StoredJSON()
    event = {'job_id': 'c02-'+case, 'attempt': 1, 'url': url}
    envelope = persist_layer(event, 'l2', native, native['raw'], store)
    loaded = load_existing_layer(event, 'l2', store)
    assert loaded == envelope and native == before
    record, raw = loaded['evidence_record'], store.get(envelope['artifact_refs']['raw'])
    audit = {}
    context = build_context([record], {'l2': raw}, audit=audit)
    view = build_judgment_view_v2(context)
    messages = capture_messages(view)
    assert json.loads(messages['messages'][0]['content']) == view
    return {'native': native, 'raw': raw, 'record': record, 'audit': audit,
            'builder-document': restore(context), 'model-document': view, 'messages-request': messages}


@pytest.mark.parametrize('case', CASES)
def test_c02_same_input_from_producer_to_messages(monkeypatch, case):
    artifacts = capture_validity(monkeypatch, case)
    record = artifacts['record']
    signal = next(x for x in record['signals'] if x['id'] == 'L2-C-02')
    native = next(x for x in artifacts['native']['signals'] if x['id'] == 'L2-C-02')
    source = next(x for x in artifacts['audit']['source_context']['observations'] if x['id'] == 'L2-C-02')
    assert signal['evidence'] == native['evidence'] == source['evidence']
    assert signal['detected'] is native['detected']
    assert artifacts['audit']['source_context']['l2_tls_source'] == artifacts['raw']['tls']
    view = artifacts['model-document']
    assert view['layer_boundaries']['model_context_version'] == VERSION
    rows = view['fact_units']
    assert not any(x['kind'] == 'check' and x['facts'].get('name') == 'certificate_validity' for x in rows)
    results = [x['facts'] for x in rows if x['kind'] == 'certificate_validity']
    status = signal['evidence'].get('status')
    if status is not None:
        assert len(results) == 1
        facts = results[0]
        assert set(facts) == {VALIDITY_LABEL, 'certificate_ref'}
        assert facts[VALIDITY_LABEL] == VALIDITY_TEXT[status]
        cert = next(x for x in rows if x['id'] == facts['certificate_ref']['evidence_ref'])
        assert cert['facts']['inspected_host'] == artifacts['raw']['tls']['hostname']
        c01 = next(x['facts'] for x in rows if x['kind'] == 'certificate_age')
        assert c01['certificate_ref'] == facts['certificate_ref']
        if case == 'different_clocks':
            assert c01[TIME_LABEL] == (NOW - timedelta(seconds=1)).isoformat()
            assert c01[AGE_LABEL] == '-1일 (유효기간 시작 전; 시간차를 24시간 단위로 내림한 값)'
            assert facts[VALIDITY_LABEL] == VALIDITY_TEXT['valid']
    else:
        assert results == []
    limits = [x['facts'] for x in rows if x['kind'] == 'certificate_validity_limit']
    if case in {'invalid_end', 'missing_end_key'}:
        assert len(limits) == 1 and limits[0]['관측 한계'] == C02_FAILED
        assert limits[0]['이유'] == native['error']['error']
        assert len([c for c in record['causes'] if c['code'] == 'analyzer_failed']) == 1
    elif case == 'missing_end':
        assert limits == [{'관측 한계': C02_UNRECORDED}]
    else:
        assert limits == []
    if case == 'absent_certificate':
        assert [x['facts'] for x in rows if x['kind'] == 'tls_observation_limit'] == [{'관측 한계': TLS_MISSING}]
        assert any(x['reason'] == 'c02_unrecorded_reason_retained_in_audit_certificate_absence_shared_in_tls'
                   for x in artifacts['audit']['model_omissions'])
        assert any(c['code'] == 'analysis_unresolved_reason_not_recorded' for c in record['causes'])
    if case in {'tls_timeout', 'no_https'}:
        code = 'tls_timeout' if case == 'tls_timeout' else 'tls_not_attempted_no_https_target'
        shared = [x['facts'] for x in rows if x['kind'] == 'limitation'
                  and x['facts'].get('description', {}).get('code') == code]
        assert len(shared) == 1
        assert 'affected_checks' not in shared[0]
        assert 'affected_signal_ids' not in shared[0]['occurrence'].get('no_entries_recorded', [])
        assert 'not_supplied' not in json.dumps(shared[0])
    if case == 'http_failure':
        assert record['coverage']['http_response_received'] is False and results
    if case == 'final_http':
        assert artifacts['raw']['tls']['hostname'] == 'example.com'
        assert artifacts['native']['target']['final_url'] == 'http://other.example.com/'


def test_c02_only_failure_has_no_dangling_check_reference(monkeypatch):
    rows = capture_validity(monkeypatch, 'tls_timeout', include_c01=False)['model-document']['fact_units']
    limit = next(x['facts'] for x in rows if x['kind'] == 'limitation'
                 and x['facts'].get('description', {}).get('code') == 'tls_timeout')
    assert 'affected_checks' not in limit
    assert 'not_supplied' not in json.dumps(limit)
    assert 'affected_signal_ids' not in limit['occurrence'].get('no_entries_recorded', [])


def test_certificate_absence_is_shared_without_relying_on_c01(monkeypatch):
    artifacts = capture_validity(monkeypatch, 'absent_certificate', include_c01=False)
    rows = artifacts['model-document']['fact_units']
    assert not any(x['kind'] in {'certificate_validity', 'certificate_validity_limit'} for x in rows)
    assert [x['facts'] for x in rows if x['kind'] == 'tls_observation_limit'] == [{'관측 한계': TLS_MISSING}]
    assert any(c['code'] == 'analysis_unresolved_reason_not_recorded' for c in artifacts['record']['causes'])


def test_absence_deduplication_does_not_depend_on_check_order(monkeypatch):
    artifacts = capture_validity(monkeypatch, 'absent_certificate')
    native = deepcopy(artifacts['native'])
    native['signals'].reverse()
    record = build_record('l2', native, raw=artifacts['raw'], request_id='reversed', attempt=1)
    rows = build_judgment_view_v2(build_context([record], {'l2': artifacts['raw']}))['fact_units']
    assert not any(x['kind'] == 'certificate_validity_limit' for x in rows)
    assert [x['facts'] for x in rows if x['kind'] == 'tls_observation_limit'] == [{'관측 한계': TLS_MISSING}]


def test_missing_raw_is_not_reinterpreted_as_certificate_absence():
    native = {'target': {'original_url': 'https://example.com/'}, 'signals': [
        {'id': 'L2-C-02', 'name': 'certificate_validity', 'detected': None, 'evidence': {'status': None}}]}
    record = build_record('l2', native, raw={}, request_id='no-raw', attempt=1)
    rows = build_judgment_view_v2(build_context([record], {'l2': {}}))['fact_units']
    assert not any(x['kind'] == 'tls_observation_limit' for x in rows)
    assert [x['facts'] for x in rows if x['kind'] == 'certificate_validity_limit'] == [{'관측 한계': C02_UNRECORDED}]


def update_accounting(view):
    ids = [row['id'] for row in view['fact_units']]
    view['source_accounting'].update(source_evidence_count=len(ids), fact_unit_count=len(ids),
        source_evidence_ids=ids, source_evidence_sha256=digest(view['fact_units']))


@pytest.mark.parametrize('field', ['not_before', 'not_after', 'status', 'detected', 'checked_at',
                                 'measured_at', 'assessment', 'state'])
def test_c02_record_details_cannot_reenter_builder_or_gateway(monkeypatch, field):
    document = capture_validity(monkeypatch)['builder-document']
    view = build_judgment_view_v2(document)
    for rows in (document['evidence'], view['fact_units']):
        next(x for x in rows if x['kind'] == 'certificate_validity')['facts'][field] = 'unexpected'
    update_accounting(view)
    with pytest.raises(ValueError, match='invalid_c02_model_fields'):
        validate_model_context(document)
    with pytest.raises(ValueError, match='invalid_c02_model_fields'):
        validate_judgment_view_v2(view)


@pytest.mark.parametrize('case', ['valid', 'tls_timeout'])
def test_c02_wrapper_cannot_reenter_final_documents(monkeypatch, case):
    document = capture_validity(monkeypatch, case)['builder-document']
    view = build_judgment_view_v2(document)
    wrapper = {'id': 'E999', 'kind': 'check', 'facts': {'layer': 'l2',
               'name': 'certificate_validity', 'detected': False, 'evidence': {'status': 'valid'}}}
    document['evidence'].append(deepcopy(wrapper))
    view['fact_units'].append(deepcopy(wrapper))
    update_accounting(view)
    with pytest.raises(ValueError, match='c02_record_wrapper'):
        validate_model_context(document)
    with pytest.raises(ValueError, match='c02_record_wrapper'):
        validate_judgment_view_v2(view)


def test_c02_requires_same_certificate_reference(monkeypatch):
    document = capture_validity(monkeypatch)['builder-document']
    row = next(x for x in document['evidence'] if x['kind'] == 'certificate_validity')
    row['facts'].pop('certificate_ref')
    with pytest.raises(ValueError, match='invalid_c02_model_fields'):
        validate_model_context(document)


@pytest.mark.parametrize('mutation', ['dates', 'detected', 'unknown_status'])
def test_inconsistent_saved_result_is_not_silently_reinterpreted(monkeypatch, mutation):
    artifacts = capture_validity(monkeypatch)
    native = deepcopy(artifacts['native'])
    signal = next(x for x in native['signals'] if x['id'] == 'L2-C-02')
    if mutation == 'dates': signal['evidence']['not_after'] = '2020-01-01T00:00:00+00:00'
    elif mutation == 'detected': signal['detected'] = True
    else: signal['evidence']['status'] = 'unrecognized'
    record = build_record('l2', native, raw=artifacts['raw'], request_id='inconsistent', attempt=1)
    with pytest.raises(ValueError, match='c02_'):
        build_context([record], {'l2': artifacts['raw']})


def test_saved_v4_keeps_its_original_c02_shape(monkeypatch):
    document = capture_validity(monkeypatch)['builder-document']
    document['model_context_version'] = 'decision-evidence-4'
    document['evidence'] = [x for x in document['evidence'] if x['kind'] != 'certificate_validity']
    document['evidence'].append({'id': 'E999', 'kind': 'check', 'facts': {'layer': 'l2',
        'name': 'certificate_validity', 'detected': False, 'evidence': {'status': 'valid'}}})
    validate_model_context(document)
    build_judgment_view_v2(document)


if __name__ == '__main__':
    output = Path(__file__).resolve().parents[2] / 'results' / 'c02-builder-20260928'
    for case in CASES:
        with pytest.MonkeyPatch.context() as patch:
            artifacts = capture_validity(patch, case)
        folder = output / case
        folder.mkdir(parents=True, exist_ok=True)
        for name, value in artifacts.items():
            (folder / (name + '.json')).write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
    print('Saved fourteen offline C02 cases from producer input through Messages.')
