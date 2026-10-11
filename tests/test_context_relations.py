from copy import deepcopy
import io,json
import pytest
from evidence_pipeline.context_relations import present,restore
from evidence_pipeline.context_inventory import present as pack,restore as unpack
from evidence_pipeline.judgment_contract import evidence_ids
from evidence_pipeline.gateway import OpenAICompatibleGateway,JudgmentServiceError

def evidence():
    return {'layers':[{'target':{'original_url':'https://club.test/'}}],
        'documents':[{'id':'document','url':'https://club.test/','title':'Club',
          'forms':[{'form_id':'form-a','action_url':'https://club.test/session','method':'GET'}],
          'inputs':[{'form_id':'form-a','field_id':'password','type':'password','name':'secret','disabled':False}],
          'buttons':[{'form_id':'form-a','button_id':'send','type':'submit','text':'Sign in',
                      'effective_action_url':'https://identity.test/login','effective_method':'POST','disabled':False}],
          'image_texts':[{'image_id':f'image-{i}','alt':'Garden','resource_url':f'https://club.test/pictures/season/spring/{i}.jpg'} for i in range(30)]}],
        'behaviors':[{'kind':'network_requests','execution_observed':False,
           'observation':{'event_id':'net-1','destination_url':'https://status.test/','source_links':[],
                          'source_excerpt':"fetch('https://status.test/',{body:'page opened'})"},'linked_sources':[]}],
        'observations':[{'id':'finding-a'}],'causes':[],'script_coverage':[]}

def test_relations_preserve_source_and_do_not_invent_payload_or_execution():
    c=evidence();v=present(c)
    assert restore(v)==c
    assert v['judgment_subject']['requested_urls_recorded']==['https://club.test/']
    f=v['recorded_relationships']['form_paths'][0]
    assert f['recorded_fields'][0]['field_id']=='password'
    assert f['recorded_submit_controls'][0]['effective_method']=='POST'
    n=v['recorded_relationships']['network_paths'][0]
    assert n['payload_relationship']=='no_payload_source_link_recorded'
    assert n['source_excerpt_recorded'].endswith("{body:'page opened'})")
    assert n['execution_observed'] is False
    assert 'verdict' not in v

def test_duplicate_form_identity_is_not_arbitrarily_joined():
    c=evidence();c['documents'][0]['forms']*=2
    rows=present(c)['recorded_relationships']['form_paths']
    assert all(x['association']=='ambiguous_duplicate_form_id' and 'recorded_fields' not in x for x in rows)

def test_unresolved_source_reference_is_not_reported_as_linked_source_evidence():
    c=evidence();c['behaviors'][0]['unresolved_source_references']=['missing-event']
    assert present(c)['recorded_relationships']['network_paths'][0]['payload_relationship']=='unresolved_source_references'

def test_inventory_retains_all_fields_ids_empty_values_and_url_suffixes():
    c=present(evidence());v=pack(c)
    assert v!=c and unpack(v)==c
    assert evidence_ids(v)==evidence_ids(c)
    assert json.loads(json.dumps(v))==v

def test_encoding_like_metadata_outside_inventory_is_not_interpreted():
    c=present(evidence());c['documents'][0]['declared_metadata']={'$literal':{'raw_content':'page text'}}
    assert unpack(pack(c))==c

@pytest.mark.parametrize('full_count,packed_count,success',[(10,10,True),(80,10,True),(80,80,False)])
def test_budget_selects_lossless_representation_before_any_judgment(full_count,packed_count,success):
    calls=[]
    def opener(request,**kwargs):
        calls.append(request)
        if request.full_url.endswith('/tokenize'):
            user=json.loads(request.data)['messages'][1]['content']
            count=packed_count if 'inventory_encoding_v2' in user else full_count
            return io.BytesIO(json.dumps({'count':count}).encode())
        return io.BytesIO(b'{"choices":[{"finish_reason":"stop","message":{"content":"{}"}}]}')
    g=OpenAICompatibleGateway('http://127.0.0.1:8000','test-key','test-model',opener=opener,
        max_context_tokens=100,max_tokens=30,structured_output=True)
    c=present(evidence())
    if success:
        selected=g.prepare_context('criteria',c)
        assert unpack(selected)==c
        n=len(calls)
        assert g('criteria',json.dumps(selected,ensure_ascii=False,separators=(',',':')))=={}
        assert len(calls)==n+1 # Prepared exact token count is reused, not measured twice.
        assert calls[-1].full_url.endswith('/v1/chat/completions')
        assert g.last_budget_check['judgment_request_attempted']
        assert g.last_budget_check['presentation']==('explicit_relationships' if full_count==10 else 'lossless_inventory')
    else:
        g.last_response={'old':'response'};g.last_request_body=b'old-request'
        with pytest.raises(JudgmentServiceError) as exc:g.prepare_context('criteria',c)
        assert exc.value.detail['kind']=='context_window_exceeded'
        assert all(x.full_url.endswith('/tokenize') for x in calls)
        assert g.last_response is None and g.last_request_body is None
        assert len(g.last_budget_check['selection_attempts'])==2

def test_prepared_budget_does_not_apply_to_different_text():
    calls=[]
    def opener(request,**kwargs):
        calls.append(request);return io.BytesIO(b'{"count":80}' if b'changed' in request.data else b'{"count":10}')
    g=OpenAICompatibleGateway('http://127.0.0.1:8000','key','model',opener=opener,max_context_tokens=100,max_tokens=30)
    g.prepare_context('criteria',present(evidence()))
    with pytest.raises(JudgmentServiceError):g('changed','{}')
    assert len(calls)==2 and g.last_request_body is None



def test_native_exclusion_does_not_erase_separately_recorded_javascript_source_link():
    c=evidence();field=c['documents'][0]['inputs'][0];field['name']=None
    c['behaviors'][0]['observation']['source_links']=[{'field_id':'password','source_event_id':'read'}]
    c['behaviors'][0]['linked_sources']=[{'event_id':'read','field_id':'password'}]
    v=present(c)
    assert v['recorded_relationships']['form_paths'][0]['recorded_fields'][0]['native_analysis_recorded']==[]
    n=v['recorded_relationships']['network_paths'][0]
    assert n['payload_relationship']=='linked_source_evidence_recorded'
    assert n['source_field_ids_recorded']==['password']
    assert restore(v)==c and unpack(pack(v))==v


def test_scope_focus_preserves_distinct_requests_responses_and_document_without_deciding_verdict():
    c=evidence();c['layers'].extend([
        {'layer':'l2','target':{'original_url':'https://club.test/private','final_url':'https://club.test/private'},
         'coverage':{'http_status_code':454,'http_response_received':True}},
        {'layer':'l3','target':{'original_url':'https://club.test/private','document_url':'https://club.test/'},
         'coverage':{'response':{'status_code':200}}}])
    v=present(c);f=v['request_observation_focus']
    assert list(v)[-1]=='request_observation_focus'
    assert f['retrievals'][0]['response_observations']['http_status_code']==454
    assert f['retrievals'][1]['response_observations']['response']['status_code']==200
    assert f['documents_recorded'][0]['url']=='https://club.test/'
    assert 'verdict' not in f and restore(v)==c


def test_fallback_tokenization_failure_keeps_both_attempt_causes_and_sends_no_judgment():
    calls=[]
    def opener(request,**kwargs):
        calls.append(request)
        if len(calls)==1:return io.BytesIO(b'{"count":80}')
        return io.BytesIO(b'{"error":"not a token count"}')
    g=OpenAICompatibleGateway('http://127.0.0.1:8000','key','model',opener=opener,max_context_tokens=100,max_tokens=30)
    with pytest.raises(JudgmentServiceError) as exc:g.prepare_context('criteria',present(evidence()))
    assert exc.value.detail['kind']=='tokenization_failed'
    attempts=g.last_budget_check['selection_attempts']
    assert len(attempts)==2 and attempts[0]['fits'] is False and attempts[1]['status']=='failed'
    assert g.last_budget_check['presentation']=='lossless_inventory'
    assert all(x.full_url.endswith('/tokenize') for x in calls)
    assert g.last_request_body is None and g.last_response is None
