"""C06 collector/analyzer -> saved record -> three selected facts -> Messages."""
from copy import deepcopy
from datetime import timedelta
import json

import httpx
import pytest

from l2_scanner import scanner
from l2_scanner.analyzers.certificate import ct_first_seen
from l2_scanner.collectors import certificate_collector, ct_collector
from evidence_pipeline import build_context, build_record
from evidence_pipeline.record_contract import validate_record
from evidence_pipeline.model_context import build_model_context, validate_model_context
from evidence_pipeline.judgment_view_v2 import build_judgment_view_v2, validate_judgment_view_v2
from evidence_pipeline.l2_ct_context import (C06, CT_TIME, CT_AGE, CT_SOURCE, CT_EMPTY, CT_NO_TIME,
    CT_NO_CERT, CT_FAILED, CT_MISSING, CT_AGE_MISSING)
from test_l2_readable_context import finish, offline
from test_l2_certificate_age_measurement import NOW, FixedClock
from test_l2_c02_context import update_accounting

CASES = ('embedded_sct', 'crt_sh', 'crt_empty', 'crt_no_timestamps', 'ct_http_error', 'ct_timeout',
    'ct_invalid_json', 'missing_certificate', 'tls_timeout', 'no_https', 'future', 'zero', 'at_30',
    'at_31', 'old', 'invalid_timestamp', 'analyzer_failed', 'http_failure', 'two_ct_failures')


def capture_ct(patch, case='embedded_sct'):
    offline(patch)
    patch.setattr(scanner, 'collect_ct', ct_collector.collect)
    patch.setattr(scanner, 'HEADER_ANALYZERS', [])
    patch.setattr(scanner, 'CERTIFICATE_ANALYZERS', [])
    patch.setattr(ct_first_seen, 'datetime', FixedClock)
    patch.setattr(scanner, '_now_iso', lambda: (NOW+timedelta(minutes=10)).isoformat())
    days = {'future': -0.25, 'zero': 0, 'at_30': 30, 'at_31': 31, 'old': 365}.get(case, 15)
    timestamp = (NOW-timedelta(days=days)).isoformat()
    scts = [timestamp, (NOW-timedelta(days=days)+timedelta(seconds=2)).isoformat()]
    if case.startswith('crt_') or case.startswith('ct_') or case == 'two_ct_failures': scts = []
    if case == 'invalid_timestamp': scts = ['invalid-date']
    leaf = {'fingerprint': 'c'*64, 'sct_timestamps': scts}
    if case == 'missing_certificate': leaf = None
    if case == 'tls_timeout':
        def failed_handshake(*args, **kwargs): raise TimeoutError('offline TLS timeout')
        patch.setattr(certificate_collector, '_handshake', failed_handshake)
    elif case != 'no_https':
        patch.setattr(scanner, 'collect_certificate', lambda host, *_: {
            'hostname': host, 'tls_version': 'TLSv1.3' if leaf else None, 'leaf_certificate': deepcopy(leaf),
            'certificate_chain': [], 'chain_valid': None, 'chain_error': None, 'errors': []})
    requests = []
    def get(url, **kwargs):
        requests.append({'url': url, 'params': kwargs['params']})
        if case == 'ct_timeout': raise httpx.ReadTimeout('offline CT timeout')
        if case in {'ct_http_error', 'two_ct_failures'}: return httpx.Response(502)
        if case == 'ct_invalid_json': return httpx.Response(200, text='not JSON')
        entries = [{'entry_timestamp': timestamp}, {'entry_timestamp': (NOW-timedelta(days=1)).isoformat()}, {'entry_timestamp': None}]
        if case == 'crt_empty': entries = []
        if case == 'crt_no_timestamps': entries = [{'entry_timestamp': None}]
        return httpx.Response(200, json=entries)
    patch.setattr(ct_collector.httpx, 'get', get)
    if case == 'analyzer_failed':
        def failed(_): raise ValueError('offline C06 analysis failed')
        patch.setattr(ct_first_seen, 'analyze', failed)
    url = ('http://' if case == 'no_https' else 'https://')+'example.com/'
    http = {'original_url': url, 'current_url': url, 'final_url': url, 'status_code': 200,
        'redirect_chain': [], 'headers': {}, 'response_body': {'body_complete': True}, 'download': {}, 'errors': []}
    if case == 'http_failure':
        http.update(final_url=None, status_code=None, errors=[{'stage': 'http', 'code': 'connection_failed', 'error': 'offline HTTP failure'}])
    native = scanner._scan_collected(http, NOW.isoformat())
    if case == 'two_ct_failures':
        native['errors'].append({'stage': 'ct', 'code': 'ct_other_failure', 'impact_scope': 'acquisition',
            'occurrence_id': 'independent-ct-failure', 'error': 'crt.sh returned HTTP 502'})
    artifacts = finish(native, url, 'c06-'+case)
    artifacts['fixture'] = {'CT_responses_are_simulated': True, 'requests': requests}
    return artifacts


@pytest.mark.parametrize('case', CASES)
def test_c06_same_input_to_messages(monkeypatch, case):
    a = capture_ct(monkeypatch, case)
    native = next(s for s in a['native']['signals'] if s['id'] == C06)
    record = next(s for s in a['record']['signals'] if s['id'] == C06)
    assert native['evidence'] == record['evidence']
    assert native['measurement_state'] == record['measurement_state']
    assert 'detected' not in native and 'detected' not in record
    assert 'fresh' not in native['evidence']
    assert a['audit']['source_context']['l2_ct_source'] == a['raw']['ct']
    rows = a['model-document']['fact_units']
    assert not any(r['kind'] == 'check' and r['facts'].get('name') == 'ct_first_seen' for r in rows)
    results = [r['facts'] for r in rows if r['kind'] == 'certificate_ct_time']
    limits = [r['facts'] for r in rows if r['kind'] == 'certificate_ct_limit']
    if native['measurement_state'] == 'observed':
        assert len(results) == 1 and not limits
        facts = results[0]
        assert set(facts) <= {CT_TIME, CT_AGE, CT_SOURCE, 'certificate_ref'}
        assert facts[CT_TIME] == native['evidence']['first_seen'] == a['raw']['ct']['first_seen']
        assert facts[CT_AGE].startswith('검사 당시 '+str(native['evidence']['age_days'])+'일')
        assert facts[CT_SOURCE] == ('crt.sh 조회' if case == 'crt_sh' else '인증서에 포함된 SCT')
        assert native['evidence']['measured_at'] == NOW.isoformat()
        assert native['evidence']['measured_at'] != a['native']['scan']['finished_at']
        if case != 'crt_sh': assert a['fixture']['requests'] == []
        assert record['assessment']['predicate'] == {'statement': 'Whole elapsed days from collected CT timestamp to measured_at', 'result': 'relationship_only'}
    else:
        assert not results
        expected = {'crt_empty': CT_EMPTY, 'crt_no_timestamps': CT_NO_TIME,
            'missing_certificate': CT_NO_CERT, 'analyzer_failed': CT_FAILED}.get(case)
        if expected:
            assert len(limits) == 1 and limits[0]['관측 한계'] == expected
        else: assert not limits
        if case == 'analyzer_failed': assert 'ValueError' in limits[0]['이유']
    if case == 'future': assert native['evidence']['age_days'] == -1
    if case in {'at_30', 'at_31'}: assert native['measurement_state'] == 'observed'
    if case == 'two_ct_failures':
        assert sum(r['kind'] == 'limitation' and r['facts'].get('description', {}).get('error') == 'crt.sh returned HTTP 502' for r in rows) == 2


@pytest.mark.parametrize('missing', ['none', 'raw', 'source', 'age'])
def test_legacy_c06_uses_recorded_values_without_new_clock(monkeypatch, missing):
    a = capture_ct(monkeypatch)
    native = deepcopy(a['native'])
    old = next(s for s in native['signals'] if s['id'] == C06)
    old.clear()
    old.update({'id': C06, 'name': 'ct_first_seen', 'detected': True,
        'evidence': {'first_seen': a['raw']['ct']['first_seen'], 'age_days': 15, 'fresh': True}})
    raw = deepcopy(a['raw'])
    if missing == 'raw': raw = {}
    if missing == 'source': raw['ct'].pop('source')
    if missing == 'age': old['evidence']['age_days'] = None
    record = build_record('l2', native, raw=raw, request_id='legacy', attempt=1)
    before = deepcopy((raw, record))
    audit = {}
    view = build_judgment_view_v2(build_context([record], {'l2': raw}, audit=audit))
    assert before == (raw, record)
    facts = next(r['facts'] for r in view['fact_units'] if r['kind'] == 'certificate_ct_time')
    assert facts[CT_TIME] == old['evidence']['first_seen']
    assert facts[CT_SOURCE] == ('미기록' if missing in {'raw', 'source'} else '인증서에 포함된 SCT')
    if missing == 'age':
        assert CT_AGE not in facts
        assert any(r['facts'].get('관측 한계') == CT_AGE_MISSING for r in view['fact_units'])
    else: assert facts[CT_AGE] == '검사 당시 15일'
    assert next(s for s in record['signals'] if s['id'] == C06)['evidence']['fresh'] is True


@pytest.mark.parametrize('field', ['detected', 'fresh', 'measured_at', 'first_seen', 'source', 'age_days'])
def test_c06_measurement_record_guards(monkeypatch, field):
    record = capture_ct(monkeypatch)['record']
    item = next(s for s in record['signals'] if s['id'] == C06)
    if field == 'detected': item['detected'] = True
    elif field == 'fresh': item['evidence']['fresh'] = True
    else: item['evidence'].pop(field)
    with pytest.raises(ValueError): validate_record(record)


@pytest.mark.parametrize('field', ['first_seen', 'source'])
def test_c06_conflicting_source_rejected(monkeypatch, field):
    source = capture_ct(monkeypatch)['audit']['source_context']
    source['l2_ct_source'][field] = 'crt.sh' if field == 'source' else '2020-01-01T00:00:00+00:00'
    with pytest.raises(ValueError, match='c06_raw_record'): build_model_context(source)


@pytest.mark.parametrize('field', ['fresh', 'detected', 'measured_at', 'sct_count', 'log_entries', 'assessment', 'missing_source', 'wrapper'])
def test_c06_unselected_fields_cannot_reenter_messages(monkeypatch, field):
    a = capture_ct(monkeypatch)
    doc = deepcopy(a['builder-document'])
    facts = next(r['facts'] for r in doc['evidence'] if r['kind'] == 'certificate_ct_time')
    if field == 'missing_source': facts.pop(CT_SOURCE)
    elif field == 'wrapper': doc['evidence'].append({'id': 'E999', 'kind': 'check', 'facts': {'layer': 'l2', 'name': 'ct_first_seen', 'detected': True}})
    else: facts[field] = True
    with pytest.raises(ValueError): validate_model_context(doc)
    view = deepcopy(a['model-document']); view['fact_units'] = doc['evidence']; update_accounting(view)
    with pytest.raises(ValueError): validate_judgment_view_v2(view)
