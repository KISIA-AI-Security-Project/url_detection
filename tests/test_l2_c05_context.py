"""C05 selection: controlled TLS outcomes through persisted records and Messages."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import ssl

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from l2_scanner import scanner
from l2_scanner.analyzers.certificate import certificate_age, certificate_validity, hostname_match, self_signed, certificate_chain
from l2_scanner.collectors import certificate_collector
from evidence_pipeline import build_context, build_record
from evidence_pipeline.model_context import build_model_context, validate_model_context, VERSION
from evidence_pipeline.judgment_view_v2 import build_judgment_view_v2, validate_judgment_view_v2
from evidence_pipeline.l2_chain_context import (C05, VERIFY_LABEL, VERIFY_PASSED, VERIFY_FAILED,
    REASON_LABEL, REASON_MISSING, SCOPE_LABEL, FAILED_SCOPE, C05_UNRECORDED, C05_ANALYSIS_FAILED)
from test_l2_readable_context import finish, offline
from test_l2_c02_context import update_accounting


CASES = ('valid', 'valid_no_export', 'expired', 'self_signed', 'unknown_issuer',
    'failure_then_reconnect_failed', 'failure_then_parse_failed', 'success_parse_failed',
    'tls_timeout', 'no_https', 'unknown_missing_reason', 'failed_missing_reason',
    'analyzer_failed', 'all_certificate_checks', 'reordered', 'http_failure', 'two_tls_failures')
FAILURES = {'expired': 'certificate has expired', 'self_signed': 'self-signed certificate',
    'unknown_issuer': 'unable to get local issuer certificate',
    'failure_then_reconnect_failed': 'offline trust rejection',
    'failure_then_parse_failed': 'offline trust rejection'}


def _der():
    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'example.com')])
    now = datetime(2026, 9, 29, tzinfo=timezone.utc)
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(5).not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('example.com')]), critical=False)
        .sign(key, None).public_bytes(Encoding.DER))


def capture_chain(patch, case='valid'):
    offline(patch)
    patch.setattr(scanner, 'HEADER_ANALYZERS', [])
    analyzers = [certificate_chain]
    if case in {'all_certificate_checks', 'reordered'}:
        analyzers = [certificate_age, certificate_validity, hostname_match, self_signed, certificate_chain]
        if case == 'reordered': analyzers.reverse()
    patch.setattr(scanner, 'CERTIFICATE_ANALYZERS', analyzers)
    der = _der()
    attempts = []
    def handshake(host, port, verify):
        attempts.append({'host': host, 'verify': verify})
        if case in {'tls_timeout', 'two_tls_failures'}:
            raise TimeoutError('offline TLS timeout')
        if verify and case in FAILURES:
            error = ssl.SSLCertVerificationError(1, FAILURES[case])
            error.verify_message = FAILURES[case]
            raise error
        if not verify and case == 'failure_then_reconnect_failed':
            raise OSError('offline certificate recollection failed')
        if case in {'failure_then_parse_failed', 'success_parse_failed'}:
            return b'invalid DER fixture', [], 'TLSv1.3'
        return der, None if case == 'valid_no_export' else [der], 'TLSv1.3'
    patch.setattr(certificate_collector, '_handshake', handshake)
    if case in {'unknown_missing_reason', 'failed_missing_reason'}:
        def collected(host, port):
            return {'hostname': host, 'tls_version': 'TLSv1.3',
                'leaf_certificate': certificate_collector._parse_certificate(der), 'certificate_chain': [],
                'chain_valid': False if case == 'failed_missing_reason' else None, 'chain_error': None, 'errors': []}
        patch.setattr(scanner, 'collect_certificate', collected)
    if case == 'analyzer_failed':
        def failed(_): raise ValueError('offline C05 analysis failed')
        patch.setattr(certificate_chain, 'analyze', failed)
    url = ('http://' if case == 'no_https' else 'https://')+'example.com/'
    http = {'original_url': url, 'current_url': url, 'final_url': url, 'status_code': 200,
        'redirect_chain': [], 'headers': {}, 'response_body': {'body_complete': True}, 'download': {}, 'errors': []}
    if case == 'http_failure':
        http.update(final_url=None, status_code=None,
            errors=[{'stage': 'http', 'code': 'connection_failed', 'error': 'offline HTTP failure'}])
    native = scanner._scan_collected(http, '2026-09-29T00:00:00+00:00')
    if case == 'two_tls_failures':
        native['errors'].append({'stage': 'tls', 'code': 'tls_timeout', 'error': 'offline TLS timeout',
            'host': 'example.com', 'impact_scope': 'acquisition', 'occurrence_id': 'separate-timeout'})
    artifacts = finish(native, url, 'c05-'+case)
    artifacts['fixture'] = {'TLS_handshakes_are_simulated': True, 'attempts': attempts}
    return artifacts


@pytest.mark.parametrize('case', CASES)
def test_c05_same_input_to_final_messages(monkeypatch, case):
    a = capture_chain(monkeypatch, case)
    native = next(s for s in a['native']['signals'] if s['id'] == C05)
    record = next(s for s in a['record']['signals'] if s['id'] == C05)
    assert native['evidence'] == record['evidence']
    assert a['audit']['source_context']['l2_tls_source'] == a['raw']['tls']
    rows = a['model-document']['fact_units']
    assert a['model-document']['layer_boundaries']['model_context_version'] == VERSION
    assert not any(r['kind'] == 'check' and r['facts'].get('name') == 'certificate_chain' for r in rows)
    results = [r['facts'] for r in rows if VERIFY_LABEL in r['facts']]
    valid = record['evidence'].get('valid')
    if type(valid) is bool:
        assert len(results) == 1
        facts = results[0]
        assert facts[VERIFY_LABEL] == (VERIFY_PASSED if valid else VERIFY_FAILED)
        if not valid:
            assert facts[REASON_LABEL] == (record['evidence']['error'] or REASON_MISSING)
            assert facts[SCOPE_LABEL] == FAILED_SCOPE
        else:
            assert REASON_LABEL not in facts
    else:
        assert not results
    for row in rows:
        if row['facts'].get('kind') == 'certificate_identity_comparison':
            assert 'chain_valid' not in row['facts']
            assert 'chain_valid' not in row['facts'].get('not_recorded', [])
    limits = [r['facts'] for r in rows if r['kind'] == 'certificate_verification_limit']
    if case == 'unknown_missing_reason': assert len(limits) == 1 and limits[0]['관측 한계'] == C05_UNRECORDED
    elif case == 'analyzer_failed': assert len(limits) == 1 and limits[0]['관측 한계'] == C05_ANALYSIS_FAILED and 'ValueError' in limits[0]['이유']
    else: assert not limits
    if case in {'valid_no_export', 'failure_then_reconnect_failed', 'failure_then_parse_failed', 'success_parse_failed'}:
        assert record['evidence']['chain_depth'] is None
        assert any(r['kind'] == 'limitation' for r in rows)
    if case == 'failure_then_reconnect_failed':
        assert not a['raw']['tls']['leaf_certificate']
        assert [x['verify'] for x in a['fixture']['attempts']] == [True, False]
        assert 'offline certificate recollection failed' in json.dumps(rows)
    if case == 'two_tls_failures':
        assert sum(r['kind'] == 'limitation' and r['facts'].get('description', {}).get('code') == 'tls_timeout' for r in rows) == 2


@pytest.mark.parametrize('valid', [True, False, None])
def test_c05_without_raw_preserves_only_recorded_result(valid):
    native = {'target': {'original_url': 'https://example.com/'}, 'signals': [
        {'id': C05, 'name': 'certificate_chain', 'detected': None if valid is None else not valid,
         'evidence': {'valid': valid, 'chain_depth': None, 'error': None}}]}
    record = build_record('l2', native, raw={}, request_id='rawless', attempt=1)
    view = build_judgment_view_v2(build_context([record], {'l2': {}}))
    rows = view['fact_units']
    if valid is None:
        assert any(r['facts'].get('관측 한계') == C05_UNRECORDED for r in rows)
    else:
        result = next(r['facts'] for r in rows if VERIFY_LABEL in r['facts'])
        assert result['검증 대상'] == 'TLS 접속 호스트 미기록'
    assert not any(r['kind'] == 'tls_observation_limit' for r in rows)


@pytest.mark.parametrize('mutation', ['raw_result', 'detected', 'raw_error', 'bool_type', 'layer_failure', 'null_detected'])
def test_c05_conflicting_observations_are_rejected(monkeypatch, mutation):
    a = capture_chain(monkeypatch, 'tls_timeout' if mutation == 'null_detected' else 'expired')
    source = deepcopy(a['audit']['source_context'])
    item = next(o for o in source['observations'] if o['id'] == C05)
    if mutation == 'raw_result': source['l2_tls_source']['chain_valid'] = True
    elif mutation in {'detected', 'null_detected'}: item['detected'] = False
    elif mutation == 'raw_error': source['l2_tls_source']['chain_error'] = 'different error'
    elif mutation == 'bool_type': item['evidence']['valid'] = 0
    else:
        source['cause_types']['conflict'] = {'code': 'analyzer_failed', 'error': 'analysis failed'}
        source['causes'].append({'id': 'conflict', 'type_id': 'conflict', 'instance': {'analyzer': C05}})
    with pytest.raises(ValueError, match='c05'):
        build_model_context(source)


@pytest.mark.parametrize('mutation', ['wrapper', 'duplicate_value', 'depth', 'ambiguous', 'safety_claim', 'missing_reason', 'missing_scope', 'duplicate_result'])
def test_c05_reentry_rejected_in_builder_and_messages(monkeypatch, mutation):
    a = capture_chain(monkeypatch, 'expired' if mutation in {'missing_reason', 'missing_scope'} else 'valid')
    doc = deepcopy(a['builder-document'])
    row = next(r for r in doc['evidence'] if VERIFY_LABEL in r['facts'])
    if mutation == 'wrapper': doc['evidence'].append({'id': 'E999', 'kind': 'check', 'facts': {'layer': 'l2', 'name': 'certificate_chain', 'detected': False}})
    elif mutation == 'duplicate_value': row['facts']['chain_valid'] = True
    elif mutation == 'depth': row['facts']['chain_depth'] = 1
    elif mutation == 'ambiguous': row['facts'][VERIFY_LABEL] = '신뢰함'
    elif mutation == 'safety_claim': row['facts'][VERIFY_LABEL] = '안전한 사이트'
    elif mutation == 'missing_reason': row['facts'].pop(REASON_LABEL)
    elif mutation == 'missing_scope': row['facts'].pop(SCOPE_LABEL)
    else: doc['evidence'].append({**deepcopy(row), 'id': 'E999'})
    with pytest.raises(ValueError): validate_model_context(doc)
    view = deepcopy(a['model-document']); view['fact_units'] = doc['evidence']; update_accounting(view)
    with pytest.raises(ValueError): validate_judgment_view_v2(view)


def test_previous_v7_contract_remains_readable(monkeypatch):
    a = capture_chain(monkeypatch)
    context = deepcopy(a['builder-document'])
    context['model_context_version'] = 'decision-evidence-7'
    row = next(r for r in context['evidence'] if VERIFY_LABEL in r['facts'])
    row['facts'].pop(VERIFY_LABEL)
    row['facts']['chain_valid'] = True
    context['evidence'].append({'id': 'E999', 'kind': 'check', 'facts': {
        'layer': 'l2', 'name': 'certificate_chain', 'detected': False,
        'evidence': {'valid': True, 'chain_depth': 1}}})
    validate_model_context(context)
    view = deepcopy(a['model-document'])
    view['layer_boundaries']['model_context_version'] = 'decision-evidence-7'
    view['fact_units'] = context['evidence']
    update_accounting(view)
    validate_judgment_view_v2(view)


@pytest.mark.parametrize('mutation', ['raw_flag', 'missing_flag', 'depth'])
def test_c05_unknown_result_reentry_rejected(monkeypatch, mutation):
    a = capture_chain(monkeypatch, 'tls_timeout')
    doc = deepcopy(a['builder-document'])
    facts = next(r['facts'] for r in doc['evidence'] if r['kind'] == 'technical')
    assert VERIFY_LABEL not in facts
    if mutation == 'raw_flag': facts['chain_valid'] = False
    elif mutation == 'missing_flag': facts.setdefault('not_recorded', []).append('chain_valid')
    else: facts['chain_depth'] = 4
    with pytest.raises(ValueError, match='c05_duplicate_fields'): validate_model_context(doc)
    view = deepcopy(a['model-document']); view['fact_units'] = doc['evidence']; update_accounting(view)
    with pytest.raises(ValueError, match='c05_duplicate_fields'): validate_judgment_view_v2(view)


def test_c05_absent_record_does_not_promote_raw_value(monkeypatch):
    a = capture_chain(monkeypatch)
    native = deepcopy(a['native'])
    native['signals'] = []
    record = build_record('l2', native, raw=a['raw'], request_id='no-c05', attempt=1)
    audit = {}
    view = build_judgment_view_v2(build_context([record], {'l2': a['raw']}, audit=audit))
    assert audit['source_context']['l2_tls_source']['chain_valid'] is True
    assert not any(VERIFY_LABEL in r['facts'] or 'chain_valid' in r['facts'] for r in view['fact_units'])
