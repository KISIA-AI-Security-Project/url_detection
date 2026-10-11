"""Readable L2 facts from offline collection/analysis through captured Messages."""
from copy import deepcopy
from datetime import datetime, timezone, timedelta
import json
import socket

import httpx
import pytest
import tldextract
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from l2_scanner import scanner
from l2_scanner.adapters import page_snapshot
from l2_scanner.analyzers.certificate import self_signed
from l2_scanner.analyzers.header import content_type_mismatch
from l2_scanner.collectors import certificate_collector
from url_collector import collect_url, CollectionPolicy
from evidence_pipeline import build_context, build_record
from evidence_pipeline.aws_runtime import persist_layer, load_existing_layer
from evidence_pipeline.context_inventory import restore
from evidence_pipeline.judgment_view_v2 import build_judgment_view_v2, validate_judgment_view_v2
from evidence_pipeline.model_context import validate_model_context
from evidence_pipeline.l2_http_context import PATH, RESPONSE
from evidence_pipeline.l2_certificate_context import SIGNATURE_LABEL, C04_NULL, C04_FAILED, C04_UNRECORDED
from test_l2_h09_context import StoredJSON, capture_messages
from test_l2_c02_context import update_accounting

HTTP_CASES = ('direct', 'initial_failure', 'destination_failure', 'no_location', 'later_no_location',
    'ip_blocked', 'shortener', 'shortener_failed', 'roundtrip', 'attachment', 'extension_only', 'mime_only',
    'both_file_matches', 'type_mismatch', 'type_alias', 'type_missing', 'refresh_target', 'refresh_delay_only',
    'refresh_unparsed', 'refresh_relative_partial', 'two_failures', 'truncated', 'reordered')


def finish(native, url, case):
    before = deepcopy(native)
    store = StoredJSON()
    event = {'job_id': 'readable-'+case, 'attempt': 1, 'url': url}
    envelope = persist_layer(event, 'l2', native, native['raw'], store)
    loaded = load_existing_layer(event, 'l2', store)
    assert loaded == envelope and native == before
    record, raw = loaded['evidence_record'], store.get(envelope['artifact_refs']['raw'])
    preserved = deepcopy((record, raw))
    audit = {}
    context = build_context([record], {'l2': raw}, audit=audit)
    view = build_judgment_view_v2(context)
    messages = capture_messages(view)
    assert json.loads(messages['messages'][0]['content']) == view
    assert preserved == (record, raw)
    return {'raw':raw, 'native':native, 'record':record, 'audit':audit,
            'builder-document':restore(context), 'model-document':view, 'messages-request':messages}


def offline(patch):
    def blocked(*args, **kwargs):
        raise AssertionError('Unexpected network access')
    patch.setattr(socket, 'create_connection', blocked)
    patch.setattr(socket, 'getaddrinfo', blocked)
    patch.setattr(tldextract, 'extract', tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None))
    patch.setattr(scanner, 'collect_ct', lambda *args: {'first_seen':'2020-01-01T00:00:00+00:00',
        'source':'offline_fixture','sct_count':0,'log_entries':1,'errors':[]})
    patch.setattr(scanner, 'CERTIFICATE_ANALYZERS_EXTENDED', [])


def capture_http(patch, case='direct'):
    offline(patch)
    patch.setattr(scanner, 'CERTIFICATE_ANALYZERS', [])
    patch.setattr(scanner, 'collect_certificate', lambda *args: {'hostname':None,'tls_version':None,
        'leaf_certificate':None,'certificate_chain':[],'chain_valid':None,'chain_error':None,'errors':[]})
    inferred = 'application/pdf'
    if case in {'mime_only','both_file_matches'}: inferred = 'application/x-dosexec'
    if case == 'type_alias': inferred = 'text/plain'
    if case == 'type_missing': inferred = None
    patch.setattr(page_snapshot, '_detect_mime', lambda _: inferred)
    url = 'https://a.example.com/report.pdf'
    if case in {'extension_only','both_file_matches'}: url = 'https://a.example.com/setup.exe'
    if case in {'shortener','shortener_failed'}: url = 'https://bit.ly/test'
    route = [url]
    if case in {'destination_failure','later_no_location','refresh_relative_partial','shortener','roundtrip'}:
        route.append('http://b.example.net/end' if case == 'destination_failure' else 'https://b.example.net/end')
    if case == 'roundtrip': route.append(url)
    if case == 'ip_blocked': route.append('http://127.0.0.1/secret')
    headers = {'content-type':'application/pdf'}
    if case == 'type_mismatch': headers['content-type'] = 'text/html'
    if case == 'type_alias': headers['content-type'] = 'application/json'
    if case == 'attachment': headers['content-disposition'] = 'attachment; filename="report.pdf"'
    if case in {'refresh_target','refresh_relative_partial'}: headers['refresh'] = '5; url=/next'
    if case == 'refresh_delay_only': headers['refresh'] = '5'
    if case == 'refresh_unparsed': headers['refresh'] = 'not-a-refresh-value'
    if case == 'two_failures':
        def failed(_): raise ValueError('separate analysis failure')
        patch.setattr(content_type_mismatch, 'analyze', failed)
    if case == 'reordered':
        patch.setattr(scanner,'HEADER_ANALYZERS',list(reversed(scanner.HEADER_ANALYZERS)))
    calls = []
    def handler(request):
        i = len(calls); calls.append(str(request.url))
        if case in {'initial_failure','shortener_failed'} or (case == 'destination_failure' and i == 1):
            raise httpx.ConnectError('offline connect failure', request=request)
        if i < len(route)-1:
            return httpx.Response(302, headers={'location':route[i+1]})
        if case in {'no_location','later_no_location','refresh_relative_partial'}:
            return httpx.Response(302, headers=headers)
        return httpx.Response(200, headers=headers, content=b'fixture body bytes')
    snapshot = collect_url(url, CollectionPolicy(2, 5, 4 if case == 'truncated' else 2000, 'offline-readable'),
        resolver=lambda *_: ('8.8.8.8',), transport=httpx.MockTransport(handler))
    native = scanner.scan_snapshot(snapshot)
    native['shared_page_observation'] = snapshot.metadata()
    if case == 'two_failures':
        # Two explicitly different occurrence IDs with the same message stay distinct.
        native['errors'].extend([{'stage':'http_body','code':'body_error','error':'same message',
            'impact_scope':'acquisition','occurrence_id':f'distinct-{i}','url':url} for i in (1,2)])
    artifacts = finish(native, url, case)
    artifacts['fixture'] = {'requests':calls,'mock_mime_classification':inferred}
    return artifacts


@pytest.mark.parametrize('case', HTTP_CASES)
def test_http_facts_reach_messages_without_wrappers(monkeypatch, case):
    a = capture_http(monkeypatch, case)
    rows = a['model-document']['fact_units']
    path = next((r['facts'] for r in rows if r['kind']=='http_journey'), None)
    assert not any(r['kind']=='check' and r['facts'].get('name') in
        {s['name'] for s in a['native']['signals'] if s['id'].startswith('L2-H-')} for r in rows)
    if case in {'initial_failure','shortener_failed'}:
        assert path is None
        assert not any(r['kind'] in {'http_content_type','http_attachment','http_refresh','http_file_type_match'} for r in rows)
    else:
        assert path
    if case in {'no_location','later_no_location','refresh_relative_partial'}:
        assert path[PATH][-1][RESPONSE] == '응답 수신'
        assert path[PATH][-1]['HTTP 응답 코드'] == 302
        assert path['경로 추적']=='완료되지 않음'
        assert '다음 주소로의 이동 지시' not in path[PATH][-1]
        assert sum(r['kind']=='http_observation_limit' for r in rows)==1
        assert all('why this check is unresolved' not in r['facts'].get('이유','') for r in rows)
    if case in {'destination_failure','ip_blocked'}:
        assert path[PATH][-1][RESPONSE]=='응답을 받지 못함'
        assert path[PATH][0]['HTTP 응답 코드']==302
        assert path['HTTPS→HTTP 이동 지시']=='관측됨'
    if case == 'ip_blocked': assert path[PATH][-1]['IP 주소로의 이동 지시']=='관측됨'
    if case == 'roundtrip':
        assert path[PATH][0]['URL']==path[PATH][-1]['URL']
        assert path['등록 도메인 관계']=='관측된 이동 경로에서 변경 있음'
    if case == 'direct': assert path['등록 도메인 관계']=='관측된 이동 경로에서 변경 없음'
    if case == 'shortener': assert path[PATH][0]['단축 서비스 목록 일치']=='bit.ly'
    if case == 'shortener_failed': assert any(r['kind']=='http_shortener_match' for r in rows)
    if case.startswith('refresh_'):
        refresh = next(r['facts'] for r in rows if r['kind']=='http_refresh')
        assert '이 지시에 따른 이동은 수행하지 않음' in refresh['관측']
        assert not any(url.endswith('/next') for url in a['fixture']['requests'])
        if case in {'refresh_delay_only','refresh_unparsed'}:
            assert '이동 대상' not in refresh and '지연 시간(초)' not in refresh
            assert refresh['Refresh 헤더 원문'] == a['raw']['http']['final_response']['headers']['refresh']
        if case == 'refresh_relative_partial': assert refresh['이동 대상']=='https://b.example.net/next'
        signal=next(s for s in a['record']['signals'] if s['id']=='L2-H-08')
        assert signal['detector_predicate']=='HTTP response contains a Refresh header'
    if case == 'extension_only':
        f=next(r['facts'] for r in rows if r['kind']=='http_file_type_match')
        assert f['목록에 해당한 확장자']=='exe'
        assert '실행파일 유형 목록에 해당한 본문 앞부분 추정 유형' not in f
    if case == 'type_alias':
        f=next(r['facts'] for r in rows if r['kind']=='http_content_type')
        assert f['유형 대조']=='설정된 동등 유형으로 취급됨'
    if case == 'two_failures':
        limits=[r['facts'] for r in rows if r['kind']=='http_observation_limit']
        assert sum(f.get('이유')=='same message' for f in limits)==2
        assert any('ValueError' in f.get('이유','') for f in limits)
    if case == 'truncated':
        coverage=next(r['facts']['coverage'] for r in rows if r['kind']=='coverage')
        assert coverage['body_truncated'] is True
    if case == 'reordered':
        f=next(r['facts'] for r in rows if r['kind']=='http_content_type')
        assert 'HTTP 경로 참조' in f


def certificate_leaf(case):
    key = ed25519.Ed25519PrivateKey.generate()
    signing = ed25519.Ed25519PrivateKey.generate() if case=='invalid_signature' else key
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'example.com')])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'issuer.example')]) if case=='different_issuer' else subject
    now = datetime(2026,9,29,tzinfo=timezone.utc)
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key()).serial_number(1).not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=30)).sign(signing,None)
    return certificate_collector._parse_certificate(cert.public_bytes(Encoding.DER))


C04_CASES = ('self_signed','different_issuer','invalid_signature','null_result','missing_key','absent_leaf','tls_failure','no_https','http_failure')


def capture_signature(patch, case='self_signed'):
    offline(patch)
    patch.setattr(scanner,'HEADER_ANALYZERS',[])
    patch.setattr(scanner,'CERTIFICATE_ANALYZERS',[self_signed])
    leaf = certificate_leaf(case)
    if case=='null_result': leaf['self_signed']=None
    if case=='missing_key': leaf.pop('self_signed')
    if case in {'absent_leaf','tls_failure','no_https'}: leaf=None
    errors=[]
    if case=='tls_failure': errors=[{'code':'tls_timeout','error':'offline TLS timeout'}]
    if case=='no_https': errors=[{'code':'tls_not_attempted_no_https_target','error':'no https target to inspect'}]
    patch.setattr(scanner,'collect_certificate',lambda host,*_: {'hostname':host,'tls_version':'TLSv1.3' if leaf else None,
        'leaf_certificate':deepcopy(leaf),'certificate_chain':[],'chain_valid':None,'chain_error':None,'errors':deepcopy(errors)})
    url=('http://' if case=='no_https' else 'https://')+'example.com/'
    http={'original_url':url,'current_url':url,'final_url':url,'status_code':200,'redirect_chain':[],
          'headers':{},'response_body':{'body_complete':True},'download':{},'errors':[]}
    if case=='http_failure': http.update(final_url=None,status_code=None,errors=[{'stage':'http','code':'connection_failed','error':'HTTP failed'}])
    native=scanner._scan_collected(http,'2026-09-29T00:00:00+00:00')
    return finish(native,url,'c04-'+case)


@pytest.mark.parametrize('case', C04_CASES)
def test_c04_leaf_crypto_result_and_limits_to_messages(monkeypatch, case):
    a=capture_signature(monkeypatch,case)
    rows=a['model-document']['fact_units']
    signs=[r['facts'][SIGNATURE_LABEL] for r in rows if SIGNATURE_LABEL in r['facts']]
    assert not any(r['facts'].get('name')=='self_signed_certificate' for r in rows)
    if case in {'self_signed','http_failure'}: assert len(signs)==1 and '서명이 검증됨' in signs[0]
    elif case in {'different_issuer','invalid_signature'}: assert len(signs)==1 and '자체 서명 인증서가 아님' in signs[0]
    else: assert not signs
    limits=[r['facts'] for r in rows if r['kind']=='certificate_signature_limit']
    if case=='null_result': assert len(limits)==1 and limits[0]['관측 한계']==C04_NULL
    elif case=='missing_key': assert len(limits)==1 and limits[0]['관측 한계']==C04_FAILED and 'KeyError' in limits[0]['이유']
    elif case=='absent_leaf': assert sum(r['kind']=='tls_observation_limit' for r in rows)==1 and not limits
    elif case in {'tls_failure','no_https'}: assert not limits and not any(r['kind']=='tls_observation_limit' for r in rows)
    native=next(x for x in a['native']['signals'] if x['id']=='L2-C-04')
    record=next(x for x in a['record']['signals'] if x['id']=='L2-C-04')
    assert native['evidence']==record['evidence']


def test_c04_missing_raw_does_not_invent_absent_certificate():
    native={'target':{'original_url':'https://example.com/'},'signals':[{'id':'L2-C-04','name':'self_signed_certificate','detected':None,'evidence':{}}]}
    record=build_record('l2',native,raw={},request_id='empty',attempt=1)
    view=build_judgment_view_v2(build_context([record],{'l2':{}}))
    assert any(r['facts'].get('관측 한계')==C04_UNRECORDED for r in view['fact_units'])
    assert not any(r['kind']=='tls_observation_limit' for r in view['fact_units'])


def test_http_missing_raw_does_not_invent_failed_response():
    native={'target':{'original_url':'https://example.com/'},'signals':[{'id':'L2-H-01','name':'redirect_chain',
        'detected':None,'evidence':{'chain':[],'final_url':None,'redirect_count':0}}]}
    record=build_record('l2',native,raw={},request_id='missing-http',attempt=1)
    view=build_judgment_view_v2(build_context([record],{'l2':{}}))
    messages=capture_messages(view)
    assert json.loads(messages['messages'][0]['content'])==view
    assert [r['facts'] for r in view['fact_units'] if r['kind']=='http_observation_limit']==[
        {'관측 한계':'HTTP 응답 수신 여부와 경로 관측 결과 미기록'}]
    assert not any(r['kind']=='http_journey' for r in view['fact_units'])


@pytest.mark.parametrize('mutation',['response_status','redirect_flag'])
def test_contradictory_http_observations_are_rejected(monkeypatch,mutation):
    from evidence_pipeline.model_context import build_model_context
    a=capture_http(monkeypatch,'roundtrip')
    source=deepcopy(a['audit']['source_context'])
    if mutation=='response_status': source['l2_http_source']['response_received']=False
    else: next(x for x in source['observations'] if x['id']=='L2-H-01')['detected']=False
    with pytest.raises(ValueError,match='l2_http_.*conflict'):
        build_model_context(source)


def test_c04_contradictory_recorded_analysis_is_rejected(monkeypatch):
    a=capture_signature(monkeypatch,'different_issuer')
    native=deepcopy(a['native'])
    native['errors'].append({'stage':'analysis','code':'analyzer_failed','error':'ValueError: failed',
        'analyzer':'L2-C-04','impact_scope':'analysis','occurrence_id':'conflicting-analysis'})
    record=build_record('l2',native,raw=a['raw'],request_id='conflict',attempt=1)
    with pytest.raises(ValueError,match='c04_result_conflicts'):
        build_context([record],{'l2':a['raw']})


@pytest.mark.parametrize('mutation',['http_wrapper','refresh_claim','download_claim','empty','c04_wrapper','c04_trust','c03_old_label'])
def test_final_messages_gate_rejects_reintroduced_ambiguity(monkeypatch,mutation):
    if mutation.startswith('c04'):
        a=capture_signature(monkeypatch)
    elif mutation=='c03_old_label':
        from test_l2_c03_context import capture_names
        a=capture_names(monkeypatch)
    else:
        a=capture_http(monkeypatch,'refresh_target' if mutation=='refresh_claim' else 'attachment')
    doc=deepcopy(a['builder-document'])
    if mutation in {'http_wrapper','c04_wrapper'}:
        doc['evidence'].append({'id':'E999','kind':'check','facts':{'layer':'l2','name':'forced_download' if mutation=='http_wrapper' else 'self_signed_certificate','detected':False}})
    elif mutation=='refresh_claim': next(r for r in doc['evidence'] if r['kind']=='http_refresh')['facts']['관측']='이동 완료'
    elif mutation=='download_claim': next(r for r in doc['evidence'] if r['kind']=='http_attachment')['facts']['관측']='브라우저에서 파일 다운로드 실행됨'
    elif mutation=='empty': next(r for r in doc['evidence'] if r['kind']=='http_attachment')['facts']['파일명']=None
    elif mutation=='c04_trust': next(r for r in doc['evidence'] if SIGNATURE_LABEL in r['facts'])['facts'][SIGNATURE_LABEL]='신뢰할 수 있는 CA가 발급함'
    else: next(r for r in doc['evidence'] if r['kind']=='technical')['facts']['인증서 이름 대조']='일치'
    with pytest.raises(ValueError): validate_model_context(doc)
    view=deepcopy(a['model-document']);view['fact_units']=doc['evidence'];update_accounting(view)
    with pytest.raises(ValueError): validate_judgment_view_v2(view)
