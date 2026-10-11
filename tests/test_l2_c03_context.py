"""C03 same-input projection, typed names, legacy scope and final-wire guards."""
from copy import deepcopy
from datetime import timedelta
import json
from pathlib import Path
import socket

import pytest

from test_l2_certificate_age_measurement import NOW, FixedClock, StoredJSON
from test_l2_h09_context import capture_messages
from test_l2_c02_context import update_accounting
from l2_scanner import scanner
from l2_scanner.analyzers.certificate import certificate_age, certificate_validity, hostname_match, ct_first_seen
from l2_scanner.collectors import certificate_collector
from evidence_pipeline import build_context, build_record
from evidence_pipeline.aws_runtime import persist_layer, load_existing_layer
from evidence_pipeline.context_inventory import restore
from evidence_pipeline.judgment_view_v2 import build_judgment_view_v2, validate_judgment_view_v2
from evidence_pipeline.model_context import validate_model_context, VERSION
from evidence_pipeline.l2_context import (NAME_LABEL, MATCHED_NAME_LABEL, DNS_NAMES_LABEL,
    IP_NAMES_LABEL, UNTYPED_NAMES_LABEL, SAN_EMPTY_LABEL, SAN_EMPTY_TEXT, C03_FAILED,
    C03_TYPES_MISSING, C03_HOST_MISSING, C03_UNRECORDED, TLS_MISSING)


CASES = ('exact', 'wildcard', 'mismatch', 'ip_match', 'ip_dns_type_mismatch', 'san_empty',
         'cn_match', 'cn_mismatch', 'legacy_dns_match', 'legacy_dns_mismatch', 'legacy_ip_unknown',
         'tls_timeout', 'no_https', 'absent_certificate', 'analyzer_failure', 'http_failure',
         'final_http', 'host_missing')


def capture_names(monkeypatch, case='exact', *, include_dates=True, reverse=False):
    def no_network(*args, **kwargs):
        raise AssertionError('C03 verification must stay offline')
    monkeypatch.setattr(socket, 'create_connection', no_network)
    monkeypatch.setattr(socket, 'getaddrinfo', no_network)
    for analyzer in (certificate_age, certificate_validity, ct_first_seen):
        monkeypatch.setattr(analyzer, 'datetime', FixedClock)
    host = '192.0.2.1' if case in {'ip_match', 'ip_dns_type_mismatch', 'legacy_ip_unknown'} else 'login.example.com'
    leaf = {'not_before': (NOW-timedelta(days=15)).isoformat(),
            'not_after': (NOW+timedelta(days=60)).isoformat(),
            'subject': 'CN='+host, 'fingerprint': 'offline', 'sct_timestamps': [],
            'san_present': True, 'san_dns': [host, 'other.example.com'], 'san_ip': []}
    if case == 'wildcard': leaf['san_dns'] = ['*.example.com', 'unused.example.net']
    if case in {'mismatch', 'legacy_dns_mismatch'}: leaf['san_dns'] = ['shop.example.net']
    if case == 'ip_match': leaf.update(san_dns=[], san_ip=[host])
    if case == 'ip_dns_type_mismatch': leaf['san_dns'] = [host]
    if case == 'san_empty': leaf.update(san_dns=[], san_ip=[])
    if case in {'cn_match', 'cn_mismatch'}:
        leaf.update(san_present=False, san_dns=[], san_ip=[])
        if case == 'cn_mismatch': leaf['subject'] = 'CN=other.example.net'
    if case == 'analyzer_failure': leaf['san_dns'] = [None]
    leaf['san'] = leaf['san_dns'] + leaf['san_ip']
    if case.startswith('legacy_'):
        for key in ('san_present', 'san_dns', 'san_ip'): leaf.pop(key)
    if case == 'absent_certificate': leaf = None
    if case == 'tls_timeout':
        def failed_handshake(*args, **kwargs):
            raise TimeoutError('offline TLS timeout')
        monkeypatch.setattr(certificate_collector, '_handshake', failed_handshake)
    elif case != 'no_https':
        def collected(hostname, port):
            return {'hostname': None if case == 'host_missing' else hostname,
                    'tls_version': 'TLSv1.3', 'leaf_certificate': deepcopy(leaf),
                    'certificate_chain': [], 'chain_valid': None, 'chain_error': None, 'errors': []}
        monkeypatch.setattr(scanner, 'collect_certificate', collected)
    monkeypatch.setattr(scanner, 'collect_ct', lambda *args: {
        'first_seen': (NOW-timedelta(days=45)).isoformat(), 'source': 'offline_fixture',
        'sct_count': 0, 'log_entries': 1, 'errors': []})
    monkeypatch.setattr(scanner, 'etld1', lambda value: 'example.com')
    monkeypatch.setattr(scanner, '_now_iso', lambda: NOW.isoformat())
    monkeypatch.setattr(scanner, 'HEADER_ANALYZERS', [])
    analyzers = [certificate_age, certificate_validity, hostname_match] if include_dates else [hostname_match]
    monkeypatch.setattr(scanner, 'CERTIFICATE_ANALYZERS', list(reversed(analyzers)) if reverse else analyzers)
    monkeypatch.setattr(scanner, 'CERTIFICATE_ANALYZERS_EXTENDED', [])
    url = ('http://' if case == 'no_https' else 'https://')+host+'/'
    http = {'original_url': url, 'final_url': url, 'current_url': url, 'status_code': 200,
            'redirect_chain': [], 'headers': {}, 'response_body': {'body_complete': True},
            'download': {}, 'errors': []}
    if case == 'http_failure':
        http.update(final_url=None, status_code=None,
                    errors=[{'stage': 'http', 'code': 'connection_failed', 'error': 'offline HTTP failure'}])
    if case == 'final_http':
        http.update(final_url='http://other.example.net/', current_url='http://other.example.net/')
    native = scanner._scan_collected(http, NOW.isoformat())
    original = deepcopy(native)
    store = StoredJSON()
    event = {'job_id': 'c03-'+case, 'attempt': 1, 'url': url}
    envelope = persist_layer(event, 'l2', native, native['raw'], store)
    loaded = load_existing_layer(event, 'l2', store)
    assert loaded == envelope and native == original
    record, raw = loaded['evidence_record'], store.get(envelope['artifact_refs']['raw'])
    audit = {}
    context = build_context([record], {'l2': raw}, audit=audit)
    view = build_judgment_view_v2(context)
    messages = capture_messages(view)
    assert json.loads(messages['messages'][0]['content']) == view
    return {'native': native, 'raw': raw, 'record': record, 'audit': audit,
            'builder-document': restore(context), 'model-document': view, 'messages-request': messages}


def certificate_row(rows):
    return next(x for x in rows if x['kind'] == 'technical' and x['facts'].get('kind') == 'certificate_identity_comparison')


@pytest.mark.parametrize('case', CASES)
def test_names_from_producer_and_saved_record_to_messages(monkeypatch, case):
    artifacts = capture_names(monkeypatch, case)
    signal = next(x for x in artifacts['record']['signals'] if x['id'] == 'L2-C-03')
    native = next(x for x in artifacts['native']['signals'] if x['id'] == 'L2-C-03')
    source = next(x for x in artifacts['audit']['source_context']['observations'] if x['id'] == 'L2-C-03')
    assert signal['evidence'] == native['evidence'] == source['evidence']
    assert signal['detected'] is native['detected']
    assert artifacts['audit']['source_context']['l2_tls_source'] == artifacts['raw']['tls']
    view = artifacts['model-document']
    assert view['layer_boundaries']['model_context_version'] == VERSION
    rows = view['fact_units']
    assert not any(x['kind'] == 'check' and x['facts'].get('name') == 'hostname_certificate_match' for x in rows)
    matches = [x for x in rows if NAME_LABEL in x['facts']]
    matched = signal['evidence'].get('matched')
    assert len(matches) == (1 if matched is not None else 0)
    if matched is not None:
        cert = certificate_row(rows)
        facts = cert['facts']
        assert matches == [cert]
        assert facts['inspected_host'] == signal['evidence']['hostname'] == artifacts['raw']['tls']['hostname']
        assert facts[NAME_LABEL].startswith('일치 (' if matched else '불일치 (')
        for result in [x for x in rows if x['kind'] in {'certificate_age', 'certificate_validity'}]:
            assert result['facts']['certificate_ref'] == {'evidence_ref': cert['id']}
        assert not any(x.get('evidence_ref') == cert['id'] for x in facts.get('source_evidence_refs', []))
        if matched:
            assert not set(facts) & {DNS_NAMES_LABEL, IP_NAMES_LABEL, UNTYPED_NAMES_LABEL, SAN_EMPTY_LABEL}
            if case == 'wildcard': assert facts[MATCHED_NAME_LABEL] == '*.example.com'
            else: assert MATCHED_NAME_LABEL not in facts
        if case in {'mismatch', 'ip_dns_type_mismatch'}:
            assert facts[DNS_NAMES_LABEL] == artifacts['raw']['tls']['leaf_certificate']['san_dns']
            assert IP_NAMES_LABEL not in facts
        if case == 'san_empty': assert facts[SAN_EMPTY_LABEL] == SAN_EMPTY_TEXT
        if case.startswith('cn_'):
            assert 'SAN 없이 CN으로 보완 대조' in facts[NAME_LABEL]
            assert not set(facts) & {DNS_NAMES_LABEL, IP_NAMES_LABEL, UNTYPED_NAMES_LABEL, SAN_EMPTY_LABEL}
        if case.startswith('legacy_dns'):
            assert '이름 유형 미기록' in facts[NAME_LABEL]
            if not matched: assert facts[UNTYPED_NAMES_LABEL] == artifacts['raw']['tls']['leaf_certificate']['san']
    for row in rows:
        if row['kind'] == 'technical':
            assert not set(row['facts']) & {'hostname_match', 'matched_name', 'certificate_alternative_names'}
    limits = [x['facts'] for x in rows if x['kind'] == 'certificate_name_limit']
    expected = {'legacy_ip_unknown': C03_TYPES_MISSING, 'analyzer_failure': C03_FAILED, 'host_missing': C03_HOST_MISSING}
    if case in expected:
        assert len(limits) == 1 and limits[0]['관측 한계'] == expected[case]
        if case == 'analyzer_failure': assert limits[0]['이유'] == native['error']['error']
    else: assert limits == []
    if case in {'tls_timeout', 'no_https'}:
        code = 'tls_timeout' if case == 'tls_timeout' else 'tls_not_attempted_no_https_target'
        shared = [x['facts'] for x in rows if x['kind'] == 'limitation'
                  and x['facts'].get('description', {}).get('code') == code]
        assert len(shared) == 1 and 'affected_checks' not in shared[0]
        assert 'not_supplied' not in json.dumps(shared[0])
        assert 'affected_signal_ids' not in shared[0]['occurrence'].get('no_entries_recorded', [])
    if case == 'absent_certificate':
        assert [x['facts'] for x in rows if x['kind'] == 'tls_observation_limit'] == [{'관측 한계': TLS_MISSING}]
    if case == 'http_failure': assert artifacts['record']['coverage']['http_response_received'] is False and matches
    if case == 'final_http': assert matches[0]['facts']['inspected_host'] == 'login.example.com'


@pytest.mark.parametrize('include_dates,reverse', [(False, False), (True, True)])
def test_common_certificate_absence_is_single_and_order_independent(monkeypatch, include_dates, reverse):
    rows = capture_names(monkeypatch, 'absent_certificate', include_dates=include_dates, reverse=reverse)['model-document']['fact_units']
    assert not any(x['kind'] == 'certificate_name_limit' or NAME_LABEL in x['facts'] for x in rows)
    assert [x['facts'] for x in rows if x['kind'] == 'tls_observation_limit'] == [{'관측 한계': TLS_MISSING}]


@pytest.mark.parametrize('field', ['hostname_match', 'matched_name', 'certificate_alternative_names',
                                 'matched', 'detected', 'comparison_scope', 'assessment'])
def test_c03_duplicate_fields_rejected_by_builder_and_gateway(monkeypatch, field):
    document = capture_names(monkeypatch)['builder-document']
    view = build_judgment_view_v2(document)
    certificate_row(document['evidence'])['facts'][field] = 'unexpected'
    certificate_row(view['fact_units'])['facts'][field] = 'unexpected'
    update_accounting(view)
    with pytest.raises(ValueError, match='c03_duplicate_fields'):
        validate_model_context(document)
    with pytest.raises(ValueError, match='c03_duplicate_fields'):
        validate_judgment_view_v2(view)


@pytest.mark.parametrize('case', ['exact', 'tls_timeout'])
def test_c03_standalone_wrapper_cannot_reenter(monkeypatch, case):
    document = capture_names(monkeypatch, case)['builder-document']
    view = build_judgment_view_v2(document)
    wrapper = {'id': 'E999', 'kind': 'check', 'facts': {'layer': 'l2', 'name': 'hostname_certificate_match',
        'detected': False, 'evidence': {'matched': True}}}
    document['evidence'].append(deepcopy(wrapper))
    view['fact_units'].append(deepcopy(wrapper))
    update_accounting(view)
    with pytest.raises(ValueError, match='c03_record_wrapper'):
        validate_model_context(document)
    with pytest.raises(ValueError, match='c03_record_wrapper'):
        validate_judgment_view_v2(view)


def test_matching_certificate_does_not_reintroduce_full_name_list(monkeypatch):
    document = capture_names(monkeypatch)['builder-document']
    certificate_row(document['evidence'])['facts'][DNS_NAMES_LABEL] = ['login.example.com', 'other.example.com']
    with pytest.raises(ValueError, match='c03_unnecessary_san_names'):
        build_judgment_view_v2(document)


def test_raw_absence_is_not_invented_when_raw_not_supplied():
    native = {'target': {'original_url': 'https://example.com/'}, 'signals': [
        {'id': 'L2-C-03', 'name': 'hostname_certificate_match', 'detected': None, 'evidence': {'matched': None}}]}
    record = build_record('l2', native, raw={}, request_id='no-raw', attempt=1)
    rows = build_judgment_view_v2(build_context([record], {'l2': {}}))['fact_units']
    assert not any(x['kind'] == 'tls_observation_limit' for x in rows)
    assert [x['facts'] for x in rows if x['kind'] == 'certificate_name_limit'] == [{'관측 한계': C03_UNRECORDED}]


@pytest.mark.parametrize('mutation', ['hostname', 'detected', 'scope', 'no_scope'])
def test_saved_result_binding_and_missing_legacy_scope(monkeypatch, mutation):
    artifacts = capture_names(monkeypatch)
    native = deepcopy(artifacts['native'])
    signal = next(x for x in native['signals'] if x['id'] == 'L2-C-03')
    if mutation == 'hostname': signal['evidence']['hostname'] = 'other.example.net'
    if mutation == 'detected': signal['detected'] = True
    if mutation == 'scope': signal['evidence']['comparison_scope'] = 'unknown-new-mode'
    if mutation == 'no_scope': signal['evidence'].pop('comparison_scope')
    record = build_record('l2', native, raw=artifacts['raw'], request_id='changed', attempt=1)
    if mutation == 'no_scope':
        rows = build_judgment_view_v2(build_context([record], {'l2': artifacts['raw']}))['fact_units']
        assert certificate_row(rows)['facts'][NAME_LABEL] == '일치 (대조 방식 미기록)'
    else:
        with pytest.raises(ValueError, match='c03_'):
            build_context([record], {'l2': artifacts['raw']})


def test_saved_v5_document_keeps_original_c03_projection(monkeypatch):
    document = capture_names(monkeypatch)['builder-document']
    document['model_context_version'] = 'decision-evidence-5'
    facts = certificate_row(document['evidence'])['facts']
    facts.pop(NAME_LABEL)
    facts['hostname_match'] = True
    document['evidence'].append({'id': 'E999', 'kind': 'check', 'facts': {'layer': 'l2',
        'name': 'hostname_certificate_match', 'detected': False, 'evidence': {'matched': True}}})
    validate_model_context(document)
    build_judgment_view_v2(document)


if __name__ == '__main__':
    output = Path(__file__).resolve().parents[2] / 'results' / 'c03-builder-20260929'
    for case in CASES:
        with pytest.MonkeyPatch.context() as patch:
            artifacts = capture_names(patch, case)
        folder = output / case
        folder.mkdir(parents=True, exist_ok=True)
        for name, value in artifacts.items():
            (folder/(name+'.json')).write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
    print('Saved eighteen offline C03 cases from producer input through Messages.')
