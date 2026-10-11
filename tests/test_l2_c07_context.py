"""C07 stays in persisted evidence; shared TLS failures still reach Messages."""
from copy import deepcopy
import json

import pytest

from l2_scanner import scanner
from l2_scanner.analyzers.certificate import certificate_chain, tls_version, wildcard_certificate
from l2_scanner.collectors import certificate_collector
from evidence_pipeline.model_context import validate_model_context
from evidence_pipeline.judgment_view_v2 import validate_judgment_view_v2
from evidence_pipeline.l2_tls_version_context import C07
from test_l2_readable_context import offline, finish
from test_l2_c05_context import _der
from test_l2_c02_context import update_accounting

CASES = ('modern', 'tls12', 'legacy', 'no_version', 'tls_timeout', 'no_https',
         'analysis_failed', 'two_tls_failures', 'shared_analysis')


def capture_version(patch, case='modern', *, certificate_analyzers=None, hostname='example.com'):
    offline(patch)
    patch.setattr(scanner, 'HEADER_ANALYZERS', [])
    patch.setattr(scanner, 'CERTIFICATE_ANALYZERS', certificate_analyzers if certificate_analyzers is not None else [certificate_chain])
    patch.setattr(scanner, 'CERTIFICATE_ANALYZERS_EXTENDED', [tls_version, wildcard_certificate])
    version = {'tls12': 'TLSv1.2', 'legacy': 'TLSv1.1', 'no_version': None}.get(case, 'TLSv1.3')
    der = _der()
    def handshake(*args, **kwargs):
        if case in {'tls_timeout', 'two_tls_failures'}:
            raise TimeoutError('offline shared TLS timeout')
        return der, [der], version
    patch.setattr(certificate_collector, '_handshake', handshake)
    if case in {'analysis_failed', 'shared_analysis'}:
        def failed(_): raise ValueError('offline C07 analysis failed')
        patch.setattr(tls_version, 'analyze', failed)
    url = ('http://' if case == 'no_https' else 'https://')+hostname+'/'
    http = {'original_url': url, 'current_url': url, 'final_url': url, 'status_code': 200,
        'redirect_chain': [], 'headers': {}, 'response_body': {'body_complete': True}, 'download': {}, 'errors': []}
    native = scanner._scan_collected(http, '2026-09-29T00:00:00+00:00')
    if case == 'two_tls_failures':
        native['errors'].append({'stage': 'tls', 'code': 'tls_timeout', 'error': 'offline shared TLS timeout',
            'impact_scope': 'acquisition', 'occurrence_id': 'separate-timeout'})
    if case == 'shared_analysis':
        # Both check-specific consumers are omitted starting with v11.
        cause = next(e for e in native['errors'] if e.get('analyzer') == C07)
        c08 = next(s for s in native['signals'] if s['id'] == 'L2-C-08')
        c08['error'] = {'causes': [deepcopy(cause)]}
    artifacts = finish(native, url, 'c07-'+case)
    artifacts['fixture'] = {'TLS_handshake_is_simulated': True,
        'shared_analysis_cause_is_synthetic': case == 'shared_analysis'}
    return artifacts


@pytest.mark.parametrize('case', CASES)
def test_c07_same_input_omission_preserves_record_and_common_causes(monkeypatch, case):
    a = capture_version(monkeypatch, case)
    native = next(s for s in a['native']['signals'] if s['id'] == C07)
    record = next(s for s in a['record']['signals'] if s['id'] == C07)
    audit_item = next(s for s in a['audit']['source_context']['observations'] if s['id'] == C07)
    assert native['evidence'] == record['evidence'] == audit_item['evidence']
    assert native['detected'] == record['detected'] == audit_item['detected']
    assert a['raw']['tls'] == a['audit']['source_context']['l2_tls_source']
    assert any('c07_tls_version_retained' in x['reason'] for x in a['audit']['model_omissions'])
    rows = a['model-document']['fact_units']
    assert not any(r['kind'] == 'check' and r['facts'].get('name') == 'tls_version' for r in rows)
    assert not any(r['kind'] == 'check' and r['facts'].get('name') == 'wildcard_certificate' for r in rows)
    assert 'tls_version' not in json.dumps(rows)
    if case != 'shared_analysis': assert C07 not in json.dumps(rows)
    limits = [r['facts'] for r in rows if r['kind'] == 'limitation']
    if case in {'tls_timeout', 'two_tls_failures'}:
        assert sum(f['description']['code'] == 'tls_timeout' for f in limits) == (2 if case == 'two_tls_failures' else 1)
    if case == 'no_https':
        assert sum(f['description']['code'] == 'tls_not_attempted_no_https_target' for f in limits) == 1
    if case in {'analysis_failed', 'no_version'}:
        assert record['cause_ids']
        assert any('c07_only_analysis_limit' in x['reason'] for x in a['audit']['model_omissions'])
        assert not limits
    if case == 'shared_analysis':
        assert not limits
        assert any('c07_c08_only_analysis_limit' in x['reason'] for x in a['audit']['model_omissions'])


@pytest.mark.parametrize('selection', ['without_c07', 'only_c07'])
def test_tls_collection_cause_survives_selected_records(monkeypatch, selection):
    a = capture_version(monkeypatch, 'tls_timeout')
    native = deepcopy(a['native'])
    native['signals'] = [s for s in native['signals'] if (s['id'] == C07) == (selection == 'only_c07')]
    view = finish(native, 'https://example.com/', selection)['model-document']
    assert sum(r['kind'] == 'limitation' and r['facts']['description']['code'] == 'tls_timeout'
               for r in view['fact_units']) == 1
    if selection == 'only_c07':
        limit = next(r['facts'] for r in view['fact_units'] if r['kind'] == 'limitation')
        assert 'affected_checks' not in limit
        assert 'affected_signal_refs' not in limit['occurrence']


@pytest.mark.parametrize('field', ['check', 'tls_field', 'missing_field', 'cause_ref', 'analysis_limit', 'limit_version', 'limit_missing_version'])
def test_c07_cannot_reenter_builder_or_messages(monkeypatch, field):
    a = capture_version(monkeypatch)
    doc = deepcopy(a['builder-document'])
    if field == 'check':
        doc['evidence'].append({'id': 'E999', 'kind': 'check',
            'facts': {'layer': 'l2', 'name': 'tls_version', 'detected': False,
                      'evidence': {'tls_version': 'TLSv1.3', 'legacy': False}}})
    elif field in {'tls_field', 'missing_field'}:
        facts = next(r['facts'] for r in doc['evidence'] if r['facts'].get('kind') == 'certificate_identity_comparison')
        if field == 'tls_field': facts['tls_version'] = 'TLSv1.3'
        else: facts.setdefault('not_recorded', []).append('tls_version')
    elif field in {'limit_version', 'limit_missing_version'}:
        detail = {'tls_version': 'TLSv1.1'} if field == 'limit_version' else {'not_recorded': ['tls_version']}
        doc['evidence'].append({'id': 'E999', 'kind': 'limitation', 'facts': {
            'occurrence': {'layer': 'l2', 'stage': 'tls', 'impact_scope': 'acquisition'},
            'observed_detail': detail, 'description': {'error': 'original TLS failure'}}})
    else:
        facts = {'occurrence': {'impact_scope': 'analysis'}, 'observed_detail': {'analyzer': C07}}
        if field == 'cause_ref': facts['occurrence']['affected_signal_ids'] = [C07]
        else: facts['affected_checks'] = []
        doc['evidence'].append({'id': 'E999', 'kind': 'limitation', 'facts': facts})
    with pytest.raises(ValueError, match='c07'): validate_model_context(doc)
    view = deepcopy(a['model-document']); view['fact_units'] = doc['evidence']; update_accounting(view)
    with pytest.raises(ValueError, match='c07'): validate_judgment_view_v2(view)
