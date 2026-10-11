"""C08 omission preserves C03 wildcard matches, mismatches and shared causes."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from l2_scanner.analyzers.certificate import certificate_chain, hostname_match, wildcard_certificate
from evidence_pipeline.l2_wildcard_context import C08
from evidence_pipeline.model_context import validate_model_context
from evidence_pipeline.judgment_view_v2 import validate_judgment_view_v2
from test_l2_readable_context import finish
from test_l2_c02_context import update_accounting
import test_l2_c07_context as version_fixture

CASES = ('wildcard_match', 'wildcard_mismatch', 'exact_plus_wildcard', 'no_wildcard',
         'tls_timeout', 'no_https', 'analysis_failed', 'shared_c03')


def capture_wildcard(patch, case='wildcard_match'):
    host = 'a.b.example.com' if case == 'wildcard_mismatch' else 'login.example.com'
    names = [host, '*.example.com'] if case == 'exact_plus_wildcard' else [host] if case == 'no_wildcard' else ['*.example.com']
    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'example.com')])
    now = datetime(2026, 9, 29, tzinfo=timezone.utc)
    der = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(8).not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
        .sign(key, None).public_bytes(Encoding.DER))
    patch.setattr(version_fixture, '_der', lambda: der)
    if case in {'analysis_failed', 'shared_c03'}:
        def failed(_): raise ValueError('offline C08 analysis failed')
        patch.setattr(wildcard_certificate, 'analyze', failed)
    a = version_fixture.capture_version(patch, case if case in {'tls_timeout', 'no_https'} else 'modern',
        certificate_analyzers=[certificate_chain, hostname_match], hostname=host)
    if case == 'shared_c03':
        native = deepcopy(a['native'])
        cause = next(e for e in native['errors'] if e.get('analyzer') == C08)
        next(s for s in native['signals'] if s['id'] == 'L2-C-03')['error'] = {'causes': [deepcopy(cause)]}
        a = finish(native, 'https://'+host+'/', 'c08-shared_c03')
    a['fixture'] = {'TLS_handshake_is_simulated': True, 'DNS_SAN': names,
        'shared_analysis_cause_is_synthetic': case == 'shared_c03'}
    return a


@pytest.mark.parametrize('case', CASES)
def test_c08_omission_and_c03_relation_reach_messages(monkeypatch, case):
    a = capture_wildcard(monkeypatch, case)
    native = next(s for s in a['native']['signals'] if s['id'] == C08)
    record = next(s for s in a['record']['signals'] if s['id'] == C08)
    audit = next(s for s in a['audit']['source_context']['observations'] if s['id'] == C08)
    assert native['evidence'] == record['evidence'] == audit['evidence']
    assert native['detected'] == record['detected'] == audit['detected']
    assert a['raw']['tls'] == a['audit']['source_context']['l2_tls_source']
    assert any('c08_wildcard_metadata_retained' in x['reason'] for x in a['audit']['model_omissions'])
    rows = a['model-document']['fact_units']
    assert not any(r['kind'] == 'check' and r['facts'].get('name') == 'wildcard_certificate' for r in rows)
    assert not any(field in json.dumps(rows) for field in ('wildcard_names', 'san_count'))
    if case not in {'no_https', 'tls_timeout'}:
        c03 = next(s for s in a['record']['signals'] if s['id'] == 'L2-C-03')['evidence']
        technical = next(r for r in rows if r['facts'].get('kind') == 'certificate_identity_comparison')
        facts = technical['facts']
        assert facts['inspected_host'] == c03['hostname']
        assert facts['TLS 접속 호스트와 인증서 이름 대조'] == ('일치' if c03['matched'] else '불일치')+' (SAN 기준)'
        if case in {'exact_plus_wildcard', 'no_wildcard'}:
            assert '일치한 인증서 이름' not in facts
        elif case == 'wildcard_mismatch':
            assert facts['인증서에 기록된 DNS 이름'] == ['*.example.com']
        else:
            assert facts['일치한 인증서 이름'] == '*.example.com'
        if case == 'shared_c03':
            limit = next(r['facts'] for r in rows if r['kind'] == 'limitation')
            assert limit['affected_checks'] == [{'evidence_ref': technical['id']}]
            assert 'offline C08 analysis failed' in limit['description']['error']
        elif case == 'analysis_failed':
            assert not any(r['kind'] == 'limitation' for r in rows)
            assert record['cause_ids']
    else:
        code = 'tls_timeout' if case == 'tls_timeout' else 'tls_not_attempted_no_https_target'
        assert sum(r['kind'] == 'limitation' and r['facts']['description']['code'] == code for r in rows) == 1


@pytest.mark.parametrize('field', ['check', 'wildcard_names', 'san_count', 'missing', 'empty', 'limit_names', 'limit_missing', 'cause'])
def test_c08_metadata_cannot_reenter_final_document(monkeypatch, field):
    a = capture_wildcard(monkeypatch)
    doc = deepcopy(a['builder-document'])
    facts = next(r['facts'] for r in doc['evidence'] if r['facts'].get('kind') == 'certificate_identity_comparison')
    if field == 'check':
        doc['evidence'].append({'id': 'E999', 'kind': 'check', 'facts': {'layer': 'l2', 'name': 'wildcard_certificate'}})
    elif field in {'wildcard_names', 'san_count'}: facts[field] = ['*.example.com'] if field == 'wildcard_names' else 1
    elif field in {'missing', 'empty'}: facts.setdefault('not_recorded' if field == 'missing' else 'no_entries_recorded', []).append('wildcard_names')
    else:
        detail = ({'wildcard_names': ['*.example.com']} if field == 'limit_names' else
                  {'not_recorded': ['san_count']} if field == 'limit_missing' else {'analyzer': C08})
        doc['evidence'].append({'id': 'E999', 'kind': 'limitation', 'facts': {
            'occurrence': {'layer': 'l2', 'impact_scope': 'analysis'}, 'observed_detail': detail}})
    with pytest.raises(ValueError, match='c08'): validate_model_context(doc)
    view = deepcopy(a['model-document']); view['fact_units'] = doc['evidence']; update_accounting(view)
    with pytest.raises(ValueError, match='c08'): validate_judgment_view_v2(view)
