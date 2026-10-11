"""Observed HTTP redirects -> native -> saved record -> Builder -> Messages."""
from copy import deepcopy
import io
import json
from pathlib import Path
import socket

import httpx
import pytest
import tldextract

from l2_scanner import scanner
from l2_scanner.adapters import page_snapshot
from l2_scanner.analyzers.header import protocol_downgrade
from url_collector import collect_url, CollectionPolicy
from evidence_pipeline import build_context
from evidence_pipeline.aws_runtime import persist_layer, load_existing_layer
from evidence_pipeline.aws_judgment_v2 import JudgmentV2Gateway, PROMPT
from evidence_pipeline.context_inventory import restore
from evidence_pipeline.judgment_view_v2 import build_judgment_view_v2, validate_judgment_view_v2
from evidence_pipeline.l2_context import DOWNGRADE_LABEL, validate_h09_selection
from evidence_pipeline.l2_http_context import PATH, RESPONSE
from evidence_pipeline.model_context import build_model_context, validate_model_context
from evidence_pipeline.records import digest


class StoredJSON:
    def __init__(self):
        self.values = {}

    def put(self, key, value, exclusive=False):
        assert not exclusive or key not in self.values
        self.values[key] = json.dumps(value)

    def get(self, key, optional=False):
        if optional and key not in self.values:
            return None
        return json.loads(self.values[key])


ROUTES = {
    'downgrade': ['https://a.example/start', 'http://b.example/end'],
    'destination_failure': ['https://a.example/start', 'http://b.example/end'],
    'twice': ['https://a.example/start', 'http://b.example/one',
              'https://a.example/two', 'http://b.example/end'],
    'upgrade': ['http://a.example/start', 'https://b.example/end'],
    'same_scheme': ['https://a.example/start', 'https://b.example/end'],
    'direct': ['https://a.example/start'],
    'initial_failure': ['https://a.example/start'],
    'analyzer_failure': ['https://a.example/start', 'http://b.example/end'],
}


def capture_messages(view):
    sent = []
    def opener(request, **kwargs):
        sent.append(json.loads(request.data))
        return io.BytesIO(json.dumps({'stop_reason': 'end_turn', 'content': [{'type': 'text',
            'text': json.dumps({'verdict': 'UNKNOWN', 'interpretation_text': 'Offline fixture',
                                'basis_fact_id_1': view['fact_units'][0]['id']})}]}).encode())
    gateway = JudgmentV2Gateway('https://example.net', 'offline-key', 'offline-model', view=view, opener=opener)
    gateway(PROMPT, json.dumps(view))
    return sent[0]


def capture_redirect(monkeypatch, case='downgrade'):
    def no_network(*args, **kwargs):
        raise AssertionError('H09 verification must stay offline')
    monkeypatch.setattr(socket, 'create_connection', no_network)
    monkeypatch.setattr(socket, 'getaddrinfo', no_network)
    monkeypatch.setattr(tldextract, 'extract', tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None))
    monkeypatch.setattr(page_snapshot, '_detect_mime', lambda _: 'text/html')
    monkeypatch.setattr(scanner, 'collect_certificate', lambda *args: {
        'hostname': None, 'tls_version': None, 'leaf_certificate': None,
        'certificate_chain': [], 'chain_valid': None, 'chain_error': None, 'errors': []})
    monkeypatch.setattr(scanner, 'collect_ct', lambda *args: {
        'first_seen': '2020-01-01T00:00:00+00:00', 'source': 'offline_fixture',
        'sct_count': 0, 'log_entries': 1, 'errors': []})
    # All real header analyzers run; separate certificate checks are outside this fixture.
    monkeypatch.setattr(scanner, 'CERTIFICATE_ANALYZERS', [])
    monkeypatch.setattr(scanner, 'CERTIFICATE_ANALYZERS_EXTENDED', [])
    if case == 'analyzer_failure':
        def failed(_):
            raise ValueError('offline H09 analysis failure')
        monkeypatch.setattr(protocol_downgrade, 'analyze', failed)
    route = ROUTES[case]
    calls = []
    def handler(request):
        index = len(calls)
        calls.append(str(request.url))
        assert str(request.url) == route[index]
        if case == 'initial_failure' or (case == 'destination_failure' and index == len(route) - 1):
            raise httpx.ConnectError('offline connection failure', request=request)
        if index < len(route) - 1:
            return httpx.Response(302, headers={'location': route[index + 1]})
        return httpx.Response(200, content=b'<html>fixture</html>', headers={'content-type': 'text/html'})
    snapshot = collect_url(route[0], CollectionPolicy(2, 5, 2000, 'offline-h09'),
        resolver=lambda *_: ('8.8.8.8',), transport=httpx.MockTransport(handler))
    native = scanner.scan_snapshot(snapshot)
    native['shared_page_observation'] = snapshot.metadata()
    before = deepcopy(native)
    store = StoredJSON()
    event = {'job_id': 'h09-' + case, 'attempt': 1, 'url': route[0]}
    envelope = persist_layer(event, 'l2', native, native['raw'], store)
    loaded = load_existing_layer(event, 'l2', store)
    assert envelope == loaded and native == before
    record = loaded['evidence_record']
    raw = store.get(envelope['artifact_refs']['raw'])
    saved = deepcopy((record, raw))
    audit = {}
    context = build_context([record], {'l2': raw}, audit=audit)
    view = build_judgment_view_v2(context)
    request = capture_messages(view)
    wire = json.loads(request['messages'][0]['content'])
    assert wire == view and saved == (record, raw)
    assert calls == route
    return {'native': native, 'raw': raw, 'record': record, 'audit': audit,
            'builder-document': restore(context), 'model-document': wire, 'messages-request': request}


@pytest.mark.parametrize('case', list(ROUTES))
def test_h09_selection_from_collector_through_final_messages(monkeypatch, case):
    artifacts = capture_redirect(monkeypatch, case)
    native = next(x for x in artifacts['native']['signals'] if x['id'] == 'L2-H-09')
    record = next(x for x in artifacts['record']['signals'] if x['id'] == 'L2-H-09')
    audited = next(x for x in artifacts['audit']['source_context']['observations'] if x['id'] == 'L2-H-09')
    assert native['evidence'] == record['evidence'] == audited['evidence']
    assert record['detected'] is native['detected']
    rows = artifacts['model-document']['fact_units']
    h01 = next((row for row in rows if row['kind'] == 'http_journey'), None)
    evidence = h01['facts'] if h01 else {}
    assert (evidence.get(DOWNGRADE_LABEL) == '관측됨') is (native['detected'] is True)
    assert set(evidence).isdisjoint({'source_url', 'destination_url', 'downgrade_count', 'upgrade_count'})
    wire_text = json.dumps(artifacts['model-document'], ensure_ascii=False)
    for excluded in ('protocol_downgrade', 'downgrade_count', 'upgrade_count', 'L2-H-09'):
        assert excluded not in wire_text
    assert wire_text.count(DOWNGRADE_LABEL) == int(native['detected'] is True)
    assert not any(row['kind']=='check' and row['facts'].get('name') in
                   {x['name'] for x in artifacts['native']['signals'] if x['id'].startswith('L2-H-')} for row in rows)
    if native['detected'] is True:
        assert [node['URL'] for node in evidence[PATH][1:]] == [hop['destination_url'] for hop in artifacts['raw']['http']['redirect_chain']]
        assert f"/observations/{next(i for i,x in enumerate(artifacts['record']['signals']) if x['id']=='L2-H-09')}" in artifacts['audit']['evidence_mapping'][h01['id']]['source_pointers']
    if case == 'twice':
        assert record['evidence']['downgrade_count'] == 2
    if case == 'destination_failure':
        assert artifacts['raw']['http']['final_response']['url'] is None
        assert evidence[PATH][-1][RESPONSE] == '응답을 받지 못함'
        assert evidence['경로 추적'] == '완료되지 않음'
    if case == 'initial_failure':
        assert h01 is None
        assert sum(row['kind']=='http_observation_limit' for row in rows)==1
    if case == 'analyzer_failure':
        assert any(c['detail'].get('analyzer') == 'L2-H-09' for c in artifacts['record']['causes'])
        assert any(x['reason'] == 'h09_only_analysis_limit_retained_in_record_and_audit'
                   for x in artifacts['audit']['model_omissions'])
    validate_h09_selection(artifacts['builder-document'])


def test_shared_limit_keeps_visible_check_without_reference_to_omitted_h09(monkeypatch):
    source = capture_redirect(monkeypatch, 'initial_failure')['audit']['source_context']
    h01 = next(x for x in source['observations'] if x['id'] == 'L2-H-01')
    h09 = next(x for x in source['observations'] if x['id'] == 'L2-H-09')
    shared = next(c for c in source['causes'] if c['id'] == h01['cause_ids'][0])
    h09['cause_ids'].append(shared['id'])
    shared['occurrence']['affected_signal_ids'].append('L2-H-09')
    before = deepcopy(source)
    audit = {}
    document = build_model_context(source, audit=audit)
    view = json.loads(capture_messages(build_judgment_view_v2(document))['messages'][0]['content'])
    assert not any(x['kind']=='http_journey' for x in view['fact_units'])
    assert 'L2-H-09' not in json.dumps(view)
    # Shared causes are retained even though the unavailable check rows are omitted.
    assert any(x['kind'] in {'http_observation_limit','limitation'} for x in view['fact_units'])
    assert source == before == audit['source_context']


@pytest.mark.parametrize('mutation', ['h01_missing', 'wrong_first_pair'])
def test_positive_h09_cannot_silently_lose_its_journey(monkeypatch, mutation):
    source = capture_redirect(monkeypatch)['audit']['source_context']
    if mutation == 'h01_missing':
        source['observations'] = [x for x in source['observations'] if x['id'] != 'L2-H-01']
    else:
        next(x for x in source['observations'] if x['id'] == 'L2-H-09')['evidence']['source_url'] = 'https://unrelated.example/'
    with pytest.raises(ValueError, match='l2_h09_'):
        build_model_context(source)


@pytest.mark.parametrize('case', ['downgrade', 'direct', 'initial_failure'])
@pytest.mark.parametrize('mutation', ['standalone', 'duplicate_detail', 'arrival_wording'])
def test_final_document_rejects_reintroduced_h09_details(monkeypatch, case, mutation):
    document = capture_redirect(monkeypatch, case)['builder-document']
    h01 = next((x for x in document['evidence'] if x['kind'] == 'http_journey'), None)
    if h01 is None and mutation != 'standalone':
        h01 = {'id':'E998','kind':'http_journey','facts':{PATH:[{'URL':'https://example.com/',RESPONSE:'응답을 받지 못함'}]}}
        document['evidence'].append(h01)
    if mutation == 'standalone':
        document['evidence'].append({'id': 'E999', 'kind': 'check',
            'facts': {'layer': 'l2', 'name': 'protocol_downgrade', 'detected': True}})
    elif mutation == 'duplicate_detail':
        h01['facts'][DOWNGRADE_LABEL] = '관측됨'
        h01['facts']['downgrade_count'] = 1
    else:
        h01['facts'][DOWNGRADE_LABEL] = 'HTTP 목적지 도착'
    with pytest.raises(ValueError, match='http|h09'):
        validate_model_context(document)


@pytest.mark.parametrize('case', ['downgrade', 'direct', 'initial_failure'])
def test_final_gateway_rejects_standalone_h09_even_without_positive_annotation(monkeypatch, case):
    view = capture_redirect(monkeypatch, case)['model-document']
    view['fact_units'].append({'id': 'E999', 'kind': 'check',
        'facts': {'layer': 'l2', 'name': 'protocol_downgrade', 'detected': False}})
    ids = [row['id'] for row in view['fact_units']]
    view['source_accounting'].update({'source_evidence_count': len(ids), 'fact_unit_count': len(ids),
        'source_evidence_ids': ids, 'source_evidence_sha256': digest(view['fact_units'])})
    with pytest.raises(ValueError, match='standalone_h09'):
        validate_judgment_view_v2(view)


def test_legacy_saved_document_remains_readable(monkeypatch):
    document = capture_redirect(monkeypatch, 'direct')['builder-document']
    document['model_context_version'] = 'decision-evidence-2'
    document['evidence'].append({'id': 'E999', 'kind': 'check',
        'facts': {'layer': 'l2', 'name': 'protocol_downgrade', 'detected': False}})
    validate_model_context(document)
    build_judgment_view_v2(document)


if __name__ == '__main__':
    output = Path(__file__).resolve().parents[2] / 'results' / 'h09-builder-20260928'
    for case in ROUTES:
        with pytest.MonkeyPatch.context() as patch:
            artifacts = capture_redirect(patch, case)
        folder = output / case
        folder.mkdir(parents=True, exist_ok=True)
        for name, value in artifacts.items():
            (folder / (name + '.json')).write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
    print('Saved eight offline HTTP journeys through captured Messages requests.')
