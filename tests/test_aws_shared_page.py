"""Real collectors/scanners -> AWS records -> model View, without external calls."""
import base64
from dataclasses import dataclass
from hashlib import sha256
from threading import Event
from time import monotonic
from types import SimpleNamespace

import httpx
import pytest

from evidence_pipeline import aws_runtime, aws_l23_shared
from evidence_pipeline.context import build_context
from evidence_pipeline.context_inventory import restore as restore_inventory
from evidence_pipeline.context_tables import restore as restore_tables
from evidence_pipeline.judgment_view_v2 import build_judgment_view_v2
from L3_SCANNER.policies import RuntimeConfig, operational_detection_policy
from unified_scanner import UnifiedScanner
from unified_scanner.config import UnifiedConfig
from url_collector import collect_url
from url_collector import ssrf


@dataclass
class Outcome:
    result: dict | None = None
    error: Exception | None = None
    timed_out: bool = False


class Store:
    def __init__(self): self.values = {}
    def get(self, key, optional=False): return self.values.get(key)
    def put(self, key, value, exclusive=False): self.values[key] = value


def legacy(runtime=None):
    return SimpleNamespace(
        Outcome=Outcome, jsonable=lambda x: x,
        l3_runtime_from_env=lambda: runtime or RuntimeConfig(fetch_external_scripts=False),
        l3_policy=operational_detection_policy, budget_seconds=lambda: 3,
        derive_reach_state=lambda l2,l3: 'ACTIVE' if l2 and l2.get('raw',{}).get('http',{}).get('final_response',{}).get('status_code') else 'INACTIVE',
        collect_outcomes=lambda *a: pytest.fail('old double-fetch entry point used'))


def install_transport(monkeypatch, handler, **scanner_options):
    import unified_scanner
    import tldextract
    offline_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
    offline_extract('example.com')
    monkeypatch.setattr(tldextract, 'extract', offline_extract)
    from l2_scanner.adapters import page_snapshot
    monkeypatch.setattr(ssrf, 'system_resolver', lambda *_: ('8.8.8.8',))
    monkeypatch.setattr(page_snapshot, '_detect_mime', lambda _: 'text/html')
    transport = httpx.MockTransport(handler)
    def factory(config, **kwargs):
        return UnifiedScanner(config, **kwargs, **scanner_options,
            collector=lambda url, policy: collect_url(url, policy,
                resolver=lambda *_: ('8.8.8.8',), transport=transport))
    monkeypatch.setattr(unified_scanner, 'UnifiedScanner', factory)


def test_one_redirect_journey_and_same_body_through_aws_records_and_view(monkeypatch):
    calls=[]
    body=b'<html><title>Shared</title><form action="/submit"><input name="pass" type="password"></form></html>'
    def handle(request):
        calls.append(str(request.url))
        if request.url.path == '/start':
            return httpx.Response(302, headers={'location':'/final', 'set-cookie':'scan=one; Path=/'})
        assert request.headers.get('cookie') == 'scan=one'
        return httpx.Response(200, content=body, headers={'content-type':'text/html'})
    install_transport(monkeypatch, handle)
    store=Store(); event={'job_id':'shared1','attempt':1,'url':'http://example.com/start'}
    result=aws_runtime.l23(event,legacy(),store)
    assert calls == ['http://example.com/start','http://example.com/final']
    rows=[store.values[result[layer]['s3_key']] for layer in ('l2','l3')]
    observations=[r['observation']['shared_page_observation'] for r in rows]
    assert observations[0] == observations[1]
    assert observations[0]['captured_body_sha256'] == sha256(body).hexdigest()
    raw2=store.values[result['l2']['raw_key']]; raw3=store.values[result['l3']['raw_key']]
    assert base64.b64decode(raw2['http']['final_response']['response_body']['captured_bytes_base64']) == body
    assert raw3['html']['source'] == body.decode()
    records=[r['evidence_record'] for r in rows]
    context=build_context(records, {'l2':raw2,'l3':raw3},max_bytes=400000)
    view=build_judgment_view_v2(context)
    coverage=[f['facts']['coverage'] for f in view['fact_units'] if f['kind']=='coverage']
    assert len(coverage)==2
    assert coverage[0]['response_observation']==coverage[1]['response_observation']
    # Same job/attempt reuse cannot fetch the page again.
    assert aws_runtime.l23(event,legacy(),store)==result
    assert len(calls)==2


@pytest.mark.parametrize('status,limit',[(404,2000),(200,40)])
def test_error_page_and_truncated_body_are_shared(monkeypatch,status,limit):
    body=b'<html><title>Observed page</title><p>'+b'x'*100+b'</p></html>'
    calls=[]
    install_transport(monkeypatch,lambda r:(calls.append(str(r.url)) or httpx.Response(status,content=body,headers={'content-type':'text/html'})))
    results=aws_l23_shared.collect_outcomes('http://example.com/',legacy(RuntimeConfig(max_html_bytes=limit)))
    assert len(calls)==1
    for result in results.values():
        meta=result.result['shared_page_observation']
        assert meta['status_code']==status
        assert meta['captured_body_sha256']==sha256(body[:limit]).hexdigest()
        assert meta['truncated']==(len(body)>limit)


def test_private_redirect_is_not_requested(monkeypatch):
    calls=[]
    install_transport(monkeypatch,lambda r:(calls.append(str(r.url)) or httpx.Response(302,headers={'location':'http://127.0.0.1/secret'})))
    store=Store()
    result=aws_runtime.l23({'job_id':'redirect_blocked','attempt':1,'url':'http://example.com/'},legacy(),store)
    assert calls==['http://example.com/']
    for layer in ('l2','l3'):
        native=store.values[result[layer]['s3_key']]['observation']
        record=store.values[result[layer]['s3_key']]['evidence_record']
        raw=store.values[result[layer]['raw_key']]
        assert native['shared_page_observation']['final_url'] is None
        assert raw['shared_page']['response_received'] is False
        assert len(native['shared_page_observation']['redirect_chain'])==1
        assert record['acquisition']['state']=='partial'
    l2_record=store.values[result['l2']['s3_key']]['evidence_record']
    h01=next(signal for signal in l2_record['signals'] if signal['id']=='L2-H-01')
    assert h01['state']=='observed'
    assert h01['evidence']['chain']==['http://127.0.0.1/secret']
    assert l2_record['coverage']['http_response_received'] is False
    records=[store.values[result[layer]['s3_key']]['evidence_record'] for layer in ('l2','l3')]
    raws={layer:store.values[result[layer]['raw_key']] for layer in ('l2','l3')}
    assert raws['l2']['http']['redirect_chain'][0]['destination_url']=='http://127.0.0.1/secret'
    document=restore_tables(restore_inventory(build_context(records,raws,max_bytes=400000)))
    model_h01=next(item['facts'] for item in document['evidence']
        if item['kind']=='http_journey')
    journey=model_h01['관측된 HTTP 경로']
    assert journey[0]['HTTP 응답 코드']==302
    assert journey[0]['다음 주소로의 이동 지시']=='관측됨'
    assert journey[1]['URL']=='http://127.0.0.1/secret'
    assert journey[1]['HTTP 응답']=='응답을 받지 못함'
    assert model_h01['경로 추적']=='완료되지 않음'
    assert any('target_policy_blocked' in item['facts'].get('이유','')
        for item in document['evidence'] if item['kind']=='http_observation_limit')


def test_l2_failure_keeps_l3_and_original_page(monkeypatch):
    body=b'<html><title>Keep me</title></html>'
    def fail(_): raise RuntimeError('analyzer crash')
    install_transport(monkeypatch,lambda r:httpx.Response(200,content=body,headers={'content-type':'text/html'}),l2_runner=fail)
    store=Store()
    result=aws_runtime.l23({'job_id':'failure1','attempt':1,'url':'http://example.com/'},legacy(),store)
    assert result['l2']['analysis_status']=='FAILED'
    assert result['l3']['analysis_status'] in {'COMPLETED','PARTIAL'}
    failed=store.values[result['l2']['s3_key']]['evidence_record']
    assert failed['acquisition']['state']=='partial'
    assert failed['analysis']['state']=='unavailable'
    raw=store.values[result['l2']['raw_key']]
    assert base64.b64decode(raw['shared_page']['captured_bytes_base64'])==body
    assert store.values[result['l3']['raw_key']]['html']['document']['title']=='Keep me'


def test_slow_layer_does_not_discard_completed_layer_or_wait_beyond_budget():
    from url_collector import CollectionPolicy
    shared=collect_url('http://example.com/',CollectionPolicy(1,0,100,'test'),
        resolver=lambda *_:('8.8.8.8',),transport=httpx.MockTransport(lambda r:httpx.Response(200,content=b'ok')))
    release=Event()
    def slow(_): release.wait(2); return {'layer':'L2'}
    quick=SimpleNamespace(scan_snapshot=lambda s:{'layer':'L3'})
    scanner=UnifiedScanner(UnifiedConfig(collection=shared.request_profile),collector=lambda *a:shared,l2_runner=slow,l3_runner=quick)
    started=monotonic()
    try:
        result=scanner.scan_url(shared.original_url,budget_seconds=.1)
        assert monotonic()-started < 1
        assert result['layers']['l3']=={'layer':'L3','scan':result['layers']['l3']['scan']}
        assert result['errors'][0]['error_type']=='LayerBudgetExceeded'
    finally: release.set()


def test_shared_page_still_fetches_external_script_under_existing_limit(monkeypatch):
    import importlib
    l3=importlib.import_module('L3_SCANNER.l3_scanner')
    fetched=[]
    def fetch(script,runtime):
        fetched.append((script.source_url,runtime.max_external_scripts))
        script.source='console.log("external");'
    monkeypatch.setattr(l3,'collect_external_script',fetch)
    body=b'<html><script src="/one.js"></script><script src="/two.js"></script></html>'
    install_transport(monkeypatch,lambda r:httpx.Response(200,content=body,headers={'content-type':'text/html'}))
    result=aws_l23_shared.collect_outcomes('http://example.com/',legacy(RuntimeConfig(fetch_external_scripts=True,max_external_scripts=1)))
    assert fetched==[('http://example.com/one.js',1)]
    scripts=result['l3'].result['raw']['javascript']['scripts']
    assert scripts[0]['source']=='console.log("external");'
    assert scripts[1]['source'] is None


def test_collection_timeout_starts_neither_analyzer():
    release=Event(); calls=[]
    def collect(*args): release.wait(2); raise RuntimeError('late collection')
    scanner=UnifiedScanner(collector=collect,l2_runner=lambda s:calls.append('l2'),
        l3_runner=SimpleNamespace(scan_snapshot=lambda s:calls.append('l3')))
    started=monotonic()
    try:
        with pytest.raises(TimeoutError): scanner.scan_url('http://example.com/',budget_seconds=.1)
        assert monotonic()-started < 1
        assert not calls
    finally: release.set()
