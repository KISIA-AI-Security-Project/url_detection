"""A failed provider call must not erase which evidence and prompt it received."""
from unittest.mock import Mock
import hashlib,io,json,urllib.error
import pytest
from evidence_pipeline import FastPipeline
from evidence_pipeline.gateway import OpenAICompatibleGateway
from evidence_pipeline.context_inventory import restore
from L3_SCANNER import L3Scanner
from L3_SCANNER.policies.operational import operational_detection_policy

@pytest.mark.parametrize('provider_fails',[False,True])
@pytest.mark.parametrize('structured_output',[False,True])
def test_pipeline_preserves_exact_api_request_and_logical_input(tmp_path,provider_fails,structured_output):
    sent=[]
    def opener(request,**kwargs):
        sent.append(request.data)
        if provider_fails:
            raise urllib.error.HTTPError(request.full_url,503,'Unavailable',{},io.BytesIO(b'{"error":{"message":"temporarily unavailable"}}'))
        payload=json.loads(request.data)
        context=restore(json.loads(payload['messages'][1]['content']))
        document_id=next(e['id'] for e in context['evidence'] if e['kind']=='page')
        value={'verdict':'LIKELY_BENIGN','summary':'정원 소식 페이지',
               'observations':[{'text':'정원 모임 일정이 있다.','evidence_ids':[document_id]}],
               'reasons':[{'text':'실제로 관측한 모임 안내가 페이지 목적을 설명한다.','evidence_ids':[document_id]}],
               'limitations':['합성 자료를 사용한 검증'],'deep_analysis_needed':False}
        return io.BytesIO(json.dumps({'choices':[{'finish_reason':'stop','message':{'content':json.dumps(value,ensure_ascii=False)}}]}).encode())
    gateway=OpenAICompatibleGateway('http://127.0.0.1:8000','private-test-authentication-key','test-model',opener=opener,disable_thinking=True,structured_output=structured_output)
    scan=L3Scanner(operational_detection_policy()).scan_content({'original_url':'https://example.com/','html':{'content':'<h1>정원 모임</h1><p>토요일 오전에 씨앗을 나눕니다.</p>'}})
    collector=Mock();collector.scan_url.return_value={'layers':{'l3':scan}}
    result=FastPipeline(collector=collector,l1_runner=lambda _:({},{}),judgment=gateway).run('https://example.com/',output_root=tmp_path,request_id='r')
    root=tmp_path/'r/1'
    assert (root/'judgment-request.json').read_bytes()==sent[0]
    assert result['judgment_request_bytes_sha256']==hashlib.sha256(sent[0]).hexdigest()
    actual=json.loads(sent[0]);logical=json.loads((root/'judgment-input.json').read_bytes())
    assert actual['messages']==[{'role':'system','content':logical['system']},{'role':'user','content':logical['user']}]
    assert logical['user']==(root/'context-for-model.json').read_text(encoding='utf-8')
    assert result['judgment_status']==('service_failed' if provider_fails else 'completed')
    complete=json.loads((root/'COMPLETE.json').read_bytes())
    assert {'judgment-input.json','judgment-request.json'}<=complete['files'].keys()
    assert b'private-test-authentication-key' not in (root/'judgment-request.json').read_bytes()
    assert 'Authorization' not in actual
    expected={'model':'test-model','messages':actual['messages'],
              'max_tokens':1600,'temperature':0,
              'chat_template_kwargs':{'enable_thinking':False}}
    if structured_output:
        from evidence_pipeline.judgment_contract import response_format
        expected['response_format']=response_format(json.loads(logical['user']))
    # Parsed-dict equality alone misses generation-order drift. Verify actual
    # wire bytes using the same ordered serializer as the frozen experiment.
    assert sent[0]==json.dumps(expected,ensure_ascii=False,separators=(',', ':')).encode()
    if structured_output:
        schema=actual['response_format']['json_schema']['schema']
        assert set(schema['properties']['verdict']['enum'])=={'MALICIOUS','LIKELY_BENIGN','SUSPICIOUS','UNKNOWN'}
        assert next(e['id'] for e in restore(json.loads(logical['user']))['evidence'] if e['kind']=='page') in schema['$defs']['evidence_id']['enum']
    else:
        assert 'response_format' not in actual
