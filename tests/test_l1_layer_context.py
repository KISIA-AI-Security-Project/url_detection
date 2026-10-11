"""Same L1 selection in the layer preview and the actual combined Messages body."""
from copy import deepcopy
import io
import json
from pathlib import Path

import pytest

from l0.registry import analyze
from evidence_pipeline import build_context, build_record
from evidence_pipeline.aws_runtime import persist_layer, load_existing_layer
from evidence_pipeline.aws_judgment_v2 import JudgmentV2Gateway, PROMPT
from evidence_pipeline.context_inventory import restore
from evidence_pipeline.judgment_view_v2 import build_judgment_view_v2, validate_judgment_view_v2
from evidence_pipeline.l1_context import build_l1_context, present_l1, KINDS
from evidence_pipeline.records import digest
from test_l0_context_wire import LocalStore
from test_l1_ns_dual_scope import _run


def capture_combined_request(monkeypatch):
    url='https://user@shop.example.test/report.pdf.exe'
    native1,raw1,_=_run(monkeypatch,'shop.example.test',rdap_fields={
        'registration':'2020-01-01T00:00:00Z','expiration':'2027-01-01T00:00:00Z',
        'last_changed':'2026-09-01T00:00:00Z','status':['client transfer prohibited'],
        'registrar':{'name':'Example Registrar','iana_id':'123'}})
    # Run the actual L1 producer for this exact URL using the controlled lookups.
    from src import handler
    native1,raw1=handler.run(url,'l01-context','1')
    native0=analyze(url)
    store=LocalStore();event={'job_id':'l01-context','attempt':1,'url':url}
    records=[];raws={};artifacts={}
    for layer,native,raw in [('l0',native0,native0['raw_evidence']),('l1',native1,raw1)]:
        original=deepcopy(native)
        envelope=persist_layer(event,layer,native,raw,store)
        loaded=load_existing_layer(event,layer,store)
        assert loaded==envelope and native==original
        records.append(loaded['evidence_record'])
        raws[layer]=store.get(envelope['artifact_refs']['raw'])
        artifacts.update({f'native-{layer}':native,f'raw-{layer}':raws[layer],f'record-{layer}':records[-1]})
    audit={};context=build_context(records,raws,audit=audit)
    explicit=restore(context);view=build_judgment_view_v2(context)
    sent=[]
    def opener(request,**kwargs):
        sent.append(json.loads(request.data))
        return io.BytesIO(json.dumps({'stop_reason':'end_turn','content':[{'type':'text',
            'text':json.dumps({'verdict':'UNKNOWN','interpretation_text':'Offline fixture',
                              'basis_fact_id_1':view['fact_units'][0]['id']})}]}).encode())
    gateway=JudgmentV2Gateway('https://example.net','offline-key','offline-model',view=view,opener=opener)
    gateway(PROMPT,json.dumps(view,ensure_ascii=False))
    assert len(sent)==1
    wire=json.loads(sent[0]['messages'][0]['content'])
    assert wire==view
    assert wire['fact_units']==explicit['evidence']
    standalone=build_l1_context(records[1],raws['l1'])
    combined_l1=present_l1(context)
    assert standalone['subject']==combined_l1['subject']
    without_ids=lambda rows:[{k:v for k,v in r.items() if k!='id'} for r in rows]
    assert without_ids(standalone['evidence'])==without_ids(combined_l1['evidence'])
    assert len({row['id'] for row in wire['fact_units']})==len(wire['fact_units'])
    assert wire['requested_urls']==[url]
    assert wire['layer_boundaries']['layer_subjects']['l1']==standalone['subject']
    assert explicit['reading_guide'].keys()=={'l0'}
    assert not any(row['kind']=='coverage' for row in wire['fact_units'])
    assert audit['source_context']['l1_raw']==raws['l1']
    artifacts.update({'audit':audit,'model-context':context,'l1-builder':standalone,
                      'final-model-document':wire,'request':sent[0]})
    return artifacts


def test_l0_l1_storage_reload_and_real_gateway_body_use_same_layer_selection(monkeypatch):
    artifacts=capture_combined_request(monkeypatch)
    assert artifacts['record-l1']['target']['original_url']==artifacts['raw-l0']['raw_url']
    model=artifacts['final-model-document']
    assert any(row['kind']=='url_observation' for row in model['fact_units'])
    assert any(row['kind']=='rdap' for row in model['fact_units'])
    assert 'code_context' not in json.dumps(model)


def test_final_wire_rejects_reintroduced_l1_metadata(monkeypatch):
    view=capture_combined_request(monkeypatch)['final-model-document']
    rdap=next(row for row in view['fact_units'] if row['kind']=='rdap')
    rdap['facts']['query_lifecycle']=[{'state':'completed'}]
    view['source_accounting']['source_evidence_sha256']=digest(view['fact_units'])
    with pytest.raises(ValueError,match='invalid_l1_model_selection'):
        validate_judgment_view_v2(view)


def test_final_wire_rejects_html_js_guide_in_l0_l1_only_input(monkeypatch):
    view=capture_combined_request(monkeypatch)['final-model-document']
    view['layer_boundaries']['reading_guide']['code_context']='unrelated HTML/JavaScript instructions'
    with pytest.raises(ValueError,match='unrelated_guide_in_l01_context'):
        validate_judgment_view_v2(view)


@pytest.mark.parametrize('name,result,expected',[
    ('RDAP','HTTP 429',{'status':'not_observed','response':'HTTP 429'}),
    ('DNS A',{'response_codes':['SERVFAIL','REFUSED']},{'response_codes':['SERVFAIL','REFUSED']}),
])
def test_unusable_received_response_keeps_its_observed_code(name,result,expected):
    native={'전체상태':'완료','인프라결과_목록':[{'name':name,'status':'응답 수신','result':result}]}
    record=build_record('l1',native,request_id='r',attempt=1,raw={})
    selected=build_l1_context(record,{})['evidence'][0]
    assert {k:v for k,v in selected.items() if k not in ('id','kind')}==expected


def test_literal_ip_keeps_direct_asn_without_fabricated_dns_pair():
    native={'전체상태':'완료','target':{'original_url':'http://192.0.2.1/','lookup_host':'192.0.2.1'},
            '인프라결과_목록':[{'name':'IP·ASN','status':'응답 수신',
              'result':{'192.0.2.1':{'asn':'64500','prefix':'192.0.2.0/24','org':'Example'}}}]}
    record=build_record('l1',native,request_id='r',attempt=1,raw={})
    model=build_l1_context(record,{})
    assert model['subject']=={'lookup_host':'192.0.2.1'}
    assert model['evidence'][0]['kind']=='ip_asn'
    assert model['evidence'][0]['networks']==[{'ip':['192.0.2.1'],'asn':'64500','prefix':'192.0.2.0/24','org':'Example'}]


def test_missing_queries_remain_simple_limits_without_inventing_timeout():
    native={'전체상태':'실패','인프라결과_목록':[],
            'query_lifecycle':[{'name':name,'state':'not_started','run_stop_reason':'budget exhausted',
                                'raw_response_recorded':False,'result_status':None}
                               for name in ('DNS A','RDAP')]}
    record=build_record('l1',native,request_id='r',attempt=1,raw={})
    model=build_l1_context(record,{})
    assert [r['lookup'] for r in model['evidence']]==['DNS A','RDAP']
    assert all(r['status']=='not_observed' for r in model['evidence'])
    assert 'Timeout' not in json.dumps(model)


def test_saved_google_snapshot_uses_exact_approved_standalone_shape():
    root=Path(__file__).parents[1]/'.test-cache/live-google-ip-asn-20260928T031949Z'
    if not (root/'record.json').exists():pytest.skip('local saved lookup snapshot absent')
    record=json.loads((root/'record.json').read_text(encoding='utf-8-sig'))
    raw=json.loads((root/'raw.json').read_text(encoding='utf-8-sig'))
    before=deepcopy(record);audit={}
    model=build_l1_context(record,raw,audit=audit)
    assert record==before and record['target']['original_url'] is None
    assert set(model)=={'layer','subject','evidence'}
    assert model['subject']=={'lookup_host':'google.com','registered_domain':'google.com'}
    assert [r['kind'] for r in model['evidence']]==['dns_a_ip_asn','dns_rdap_ns_comparison','rdap']
    assert model['evidence'][0]['networks']==[{
        'ipv4':['142.251.15.138','142.251.15.101'],'asn':'15169','prefix':'142.251.15.0/24','org':'GOOGLE - Google LLC, US'}]
    assert model['evidence'][1]=={'id':'E2','kind':'dns_rdap_ns_comparison','status':'matched'}
    assert model['evidence'][2]['expiration']=='2028-09-14T04:00:00Z'
    assert audit['source_context']['l1_raw']==raw


if __name__=='__main__':
    import sys
    destination=Path(sys.argv[1]).resolve();destination.mkdir(parents=True,exist_ok=True)
    with pytest.MonkeyPatch.context() as monkeypatch:
        for name,value in capture_combined_request(monkeypatch).items():
            (destination/(name+'.json')).write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print('Saved offline L0/L1 native, raw, reloaded record, layer output, audit and captured Messages body.')
