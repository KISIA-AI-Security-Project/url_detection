"""Independent evidence-preservation, cause-separation and reference checks."""
from copy import deepcopy
import json
import pytest
from L3_SCANNER.analyzers.html.brand_domain_mismatch import analyze as domain
from L3_SCANNER.analyzers.html.brand_resource_mismatch import analyze as resource
from L3_SCANNER.policies.detection import DetectionPolicy
from evidence_pipeline.records import build_record, canonical
from evidence_pipeline.context_view import present_context, pack_rows, unpack_rows, document_interactions
from evidence_pipeline.pipeline import validate_judgment, render_context

RAW = {'document': {'parse_succeeded': True}, 'images': [], 'open_graph': {}}
URL = 'https://example.com/'

@pytest.mark.parametrize('analyzer,first,second,expected', [
    (domain, DetectionPolicy(), DetectionPolicy(brand_identifier=lambda _: None),
     ('brand_identifier_not_configured', 'brand_not_identified')),
    (domain, DetectionPolicy(brand_identifier=lambda _: 'Example'),
     DetectionPolicy(brand_identifier=lambda _: 'Example', brand_expected_domains={}),
     ('brand_domain_reference_not_configured', 'brand_absent_from_domain_reference')),
    (resource, DetectionPolicy(), DetectionPolicy(brand_resource_rules={'evaluator': lambda _: None}),
     ('brand_resource_evaluator_not_configured', 'brand_resource_evaluator_abstained')),
    (resource, DetectionPolicy(brand_resource_rules={'evaluator': None}),
     DetectionPolicy(brand_resource_rules={'evaluator': 3}),
     ('brand_resource_evaluator_not_configured', 'brand_resource_evaluator_invalid')),
    (resource, DetectionPolicy(brand_resource_rules={'evaluator': lambda _: None}),
     DetectionPolicy(brand_resource_rules={'evaluator': lambda _: 'yes'}),
     ('brand_resource_evaluator_abstained', 'brand_resource_evaluator_invalid_result')),
])
def test_distinct_unresolved_causes_survive_into_record(analyzer, first, second, expected):
    results = [analyzer(RAW, URL, policy) for policy in (first, second)]
    codes = []
    for result in results:
        assert result['detected'] is None
        record = build_record('l3', {'signals': [result]}, request_id='r', attempt='1', raw={'html': RAW})
        assert record['signals'][0]['state'] == 'unresolved'
        assert record['signals'][0]['cause_ids']
        codes.append({c['code'] for c in record['causes']})
    assert expected[0] in codes[0] - codes[1]
    assert expected[1] in codes[1] - codes[0]


def test_missing_identifier_does_not_become_brand_absence_fact():
    result = domain(RAW, URL, DetectionPolicy())
    assert result['evidence']['detected_brand'] is None
    assert 'brand_not_identified' not in {x['code'] for x in result['limitations']}


def test_unknown_legacy_reason_is_explicit_without_inventing_a_cause():
    record = build_record('l3', {'signals': [{'id':'L3-H-05','name':'brand','status':'evaluated','detected':None}]}, request_id='r', attempt='1')
    assert record['causes'][0]['code'] == 'analysis_unresolved_reason_not_recorded'
    assert 'not_configured' not in json.dumps(record)


def fixture_source():
    return {'question':'Assess the requested link', 'observations':[
        {'id':'risk-looking-name','name':'external payment destination','layer':'l3','state':'observed', 'detected':True,
         'evidence':{'destination':'https://pay.example.net/','login':False,'unknown':None,'items':[]}, 'cause_ids':[],
         'record_reference':{'key':'record-l3.json','pointer':'/signals/0'}},
        {'id':'negative','name':'credential collection','layer':'l3','state':'not_observed_in_analyzed_scope','detected':False,'evidence':{'count':0},'cause_ids':[]},
        {'id':'unknown','name':'brand comparison','layer':'l3','state':'unresolved','detected':None,'evidence':{'brand':None},'cause_ids':[]},
    ], 'documents':[{'id':'document','url':URL,'text':'An ordinary shop offers payment.', 'forms':[{'id':'document','form_id':'checkout'}],
                      'inputs':[],'buttons':[],'raw_reference':{'sha256':'a'*64}}],
    'causes':[], 'layers':[{'layer':'l3','status':'PARTIAL','target':{'original_url':URL},'coverage':{'html_parsed':True},'provenance':{'mode':'current'}}],
    'behaviors':[], 'technical_facts':[], 'script_coverage':[], 'omissions':[]}


def test_all_positive_negative_unknown_facts_and_document_content_survive():
    source = fixture_source(); unchanged = deepcopy(source); audit = {}
    view = present_context(source, audit=audit)
    assert source == unchanged
    assert [o['result'] for o in view['observations']] == ['found','not_found','unresolved']
    assert [o['facts'] for o in view['observations']] == [o['evidence'] for o in source['observations']]
    assert view['documents'][0]['text'] == source['documents'][0]['text']
    assert view['documents'][0]['forms'][0]['id'] == 'document'  # Actual HTML IDs cannot be rewritten.
    assert view['causes'][0]['code'] == 'analysis_unresolved_reason_not_recorded'
    assert view['target']['requested_url'] == URL
    assert 'verdict' not in view
    assert audit['evidence_references']['E1']['record_reference']['pointer'] == '/signals/0'
    assert 'record_reference' not in json.dumps(view)


def test_table_inventory_is_exact_and_preserves_zero_false_null_empty_values():
    items = [{'image_id':f'image-{i}','alt':str(i),'resource_url':f'https://cdn.example/{i}.png',
              'scope':'declared alternative text; image not visually interpreted','zero':0,'false':False,'null':None,'empty':[]}
             for i in range(100)]
    packed = pack_rows(items)
    assert isinstance(packed, dict)
    assert len(canonical(packed)) < len(canonical(items)) / 2
    assert unpack_rows(packed) == items


def test_different_inventory_shapes_are_not_padded_with_fake_values():
    items = [{'id':str(i),'a':None} for i in range(20)] + [{'id':'last'}]
    assert pack_rows(items) == items


def test_validator_accepts_only_supplied_short_ids_and_inventory_ids():
    source = fixture_source()
    source['documents'][0]['image_texts'] = [{'image_id':f'im{i}','alt':'shop','scope':'declared alt','resource_url':f'/i{i}'} for i in range(20)]
    view = present_context(source)
    verdict = {'verdict':'UNKNOWN','summary':'Insufficient','reasons':[{'text':'Review image','evidence_ids':['im19']}],
               'observations':[{'text':'Shop','evidence_ids':['D1']}],'limitations':[],'deep_analysis_needed':True}
    assert validate_judgment(verdict, view, require_observations=True) == verdict
    verdict['reasons'][0]['evidence_ids'] = ['E999']
    with pytest.raises(ValueError, match='invalid_evidence_reference'):
        validate_judgment(verdict, view)


def test_model_message_order_and_budget_do_not_silently_drop_evidence():
    source = fixture_source(); view = present_context(source)
    message = render_context(view)
    assert message.index('"question"') < message.index('"documents"') < message.index('"observations"')
    with pytest.raises(ValueError, match='context_budget_exceeded'):
        present_context(source, max_bytes=100)


def test_interaction_keeps_submit_override_and_excludes_non_submit_button():
    from L3_SCANNER.parsers.html_parser import parse_html
    raw = parse_html('<form id="f" action="/default"><input id="p" type="password"><button id="submit" formaction="https://pay.example.net/" formmethod="post">Pay</button><button id="local" type="button">Open help</button></form>', URL)
    doc = {'id':'D1','url':URL,**{k:raw[k] for k in ['forms','inputs','buttons']}}
    interaction = document_interactions([doc])[0]
    assert interaction['input_ids'] == ['p']
    assert len(interaction['submissions']) == 2
    submit = interaction['submissions'][1]
    assert submit['target_url'] == 'https://pay.example.net/' and submit['method'] == 'post'
    assert submit['same_origin'] is False and interaction['execution_observed'] is False


def test_generated_reference_ids_cannot_collide_with_page_ids():
    source = fixture_source()
    source['documents'][0]['forms'] = [{'form_id':'E1','id':'D1'}]
    view = present_context(source)
    assert view['observations'][0]['id'] != 'E1'
    assert view['documents'][0]['id'] != 'D1'
    assert view['documents'][0]['forms'][0] == source['documents'][0]['forms'][0]


@pytest.mark.parametrize('value', [True,False])
def test_certificate_predicate_has_same_polarity_as_its_fact(value):
    source = fixture_source()
    source['observations'] = [{'id':'L2-C-03','name':'hostname match','layer':'l2',
        'state':'not_observed_in_analyzed_scope' if value else 'observed','detected':not value,
        'evidence':{'matched':value},'cause_ids':[]}]
    audit={};view=present_context(source,audit=audit);check=view['observations'][0]
    assert check['check']=='certificate hostname matches the inspected host'
    assert (check['result']=='found') is value
    assert check['facts']['matched'] is value and audit['check_result_normalizations']


def test_duplicate_historical_form_ids_do_not_invent_a_definite_association():
    docs=[{'id':'D1','url':URL,'forms':[{'form_id':'f','action_url':'/a'},{'form_id':'f','action_url':'/b'}],
           'inputs':[{'field_id':'password','form_id':'f'}],'buttons':[]}]
    interactions=document_interactions(docs)
    assert len(interactions)==2
    assert all(x['association_status']=='unresolved_duplicate_form_id' and 'input_ids' not in x for x in interactions)
