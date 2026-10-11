"""Independent review: occurrence-bound facts, limits, and actual Fast transport.

These are offline producer inputs. Fixed model responses verify transport and
public evidence linkage only, never URL judgment quality.
"""
from copy import deepcopy

import pytest

from evidence_pipeline.fast_context import build_fast_context
from evidence_pipeline.records import digest
from test_l3_javascript_text import capture, document, assert_preserved


CHAIN = "fetch('/screen').then(response => response.text()).then(html => {document.open();document.write(html);document.close();})"
CLICK = '''document.addEventListener('click', function(e) {
  const target = e.target.closest('#join, ' + '.login');
  if (target) {
    e.preventDefault();e.stopPropagation();e.stopImmediatePropagation();
    %s;
  }
}, true);''' % CHAIN


def requests(a):
    return a['raw']['javascript']['network_requests']


def context(a, i=0):
    return requests(a)[i].get('request_context', {})


def signal(bundle, identifier='L3-J-04'):
    return next(s for s in bundle['signals'] if s['id'] == identifier)


def refresh_binding(a):
    """Rebind synthetic artifacts after an explicit test-only raw mutation."""
    values = [{key: deepcopy(event[key]) for key in (
        'event_id', 'script_id', 'source_range', 'call_context',
        'control_context', 'request_context')}
        for event in requests(a) if event.get('request_context')]
    for owner in (a['record'], a['native']):
        evidence = signal(owner)['evidence']
        if values:
            evidence['request_contexts'] = deepcopy(values)
        else:
            evidence.pop('request_contexts', None)
    a['native']['raw'] = deepcopy(a['raw'])
    a['record']['raw_ref']['sha256'] = digest(a['raw'])


@pytest.mark.parametrize('combined', [False, True])
def test_click_request_relationships_are_produced_stored_selected_and_transported(combined):
    a = capture(CLICK)
    before = deepcopy(a)
    request, ctx = requests(a)[0], context(a)
    assert ctx['execution_observed'] is False
    assert ctx['registration']['event_type'] == 'click'
    assert ctx['condition_binding']['selector'] == '#join, .login'
    assert [v['api'] for v in ctx['event_controls']] == [
        'e.preventDefault', 'e.stopPropagation', 'e.stopImmediatePropagation']
    assert ctx['response_flow']['kind'] == 'fetch_text_to_document_write'
    stored = signal(a['record'])['evidence']['request_contexts']
    assert stored[0]['event_id'] == request['event_id']
    assert stored[0]['source_range'] == request['source_range']
    assert stored[0]['request_context'] == ctx
    doc = document(a, combined)
    for marker in ('click', '#join, .login', 'preventDefault', '응답 처리의 정적 연결', 'document.write'):
        assert marker in doc.body
    assert '실제 응답 내용' in doc.body and '관측한 결과가 아님' in doc.body
    assert CLICK not in doc.body
    assert_preserved(a, doc)
    assert a == before


def test_unrelated_constants_comments_and_functions_do_not_enter_model_document():
    source = ("const unused='UNUSED_REVIEW_SENTINEL';/* IRRELEVANT_REVIEW_COMMENT */"
              "function unrelatedView(){document.write('UNRELATED_REVIEW_VIEW')}" + CLICK)
    a = capture(source)
    assert context(a)['response_flow']
    body = document(a).body
    for marker in ('UNUSED_REVIEW_SENTINEL', 'IRRELEVANT_REVIEW_COMMENT', 'UNRELATED_REVIEW_VIEW'):
        assert marker not in body
        assert marker in a['raw']['javascript']['scripts'][0]['source']


def test_unreachable_literal_branch_keeps_static_scope_in_body_and_direct_fact():
    a = capture(CLICK.replace('if (target)', 'if (false)'))
    assert context(a)['registration']['event_type'] == 'click'
    assert context(a)['response_flow']
    assert not context(a).get('condition_binding')
    assert '리터럴 조건은 이 갈래의 진입 조건과 맞지 않음' in document(a).body
    fast = build_fast_context([a['record']], {'l3': a['raw']}, native=a['native'])
    fact = next(f for f in fast['details']['facts'] if f['title'] == '요청 구문 1')
    assert 'false' in fact['text']
    assert '실제' in fact['plain']['text']
    assert '정적' in fact['plain']['text']


@pytest.mark.parametrize('source', [
    "function get(){fetch('/screen')}function show(html){document.write(html)}get();",
    "document.addEventListener('click', handler);function handler(e){fetch('/screen')}",
    "document.addEventListener('click', function(e){function nested(){fetch('/screen')}nested()});",
])
def test_named_or_independent_function_is_not_given_an_invented_callback_binding(source):
    a = capture(source)
    assert requests(a)
    assert all(not e.get('request_context', {}).get('registration') for e in requests(a))
    assert all(not e.get('request_context', {}).get('response_flow') for e in requests(a))


@pytest.mark.parametrize('mutation', [
    'e = other;', '[e] = [other];', '({e} = other);',
    'e.target = other;', "e['target'] = other;",
])
def test_reassigned_event_parameter_does_not_bind_selector_or_event_controls(mutation):
    a = capture(CLICK.replace('const target', mutation + 'const target'))
    assert requests(a)
    assert not context(a).get('condition_binding')
    assert not context(a).get('event_controls')


@pytest.mark.parametrize('source', [
    CHAIN.replace('response => response.text()', "response => {response.text();return 'fixed';}"),
    CHAIN.replace('html => {', "html => {html='fixed';"),
    CHAIN.replace('html => {', "html => {[html]=['fixed'];"),
    CHAIN.replace('html => {', "html => {({html}=other);"),
    CHAIN.replace('.then(html', '.then(x => x.toUpperCase()).then(html'),
    CHAIN.replace('response => response.text())', 'response => response.text(), err => "fallback")'),
    CHAIN.replace('response => response.text()', '({response}) => response.text()'),
    CHAIN.replace('response => response.text()', 'async response => response.text()'),
    CHAIN.replace('document.write(html)', 'otherDocument.write(html)'),
    CHAIN.replace('document.write(html)', 'getRoot().document.write(html)'),
    CHAIN.replace('document.write(html)', 'document.write("fixed")'),
])
def test_changed_or_unsupported_response_value_is_not_connected_to_document_write(source):
    a = capture(source)
    assert requests(a)
    assert not context(a).get('response_flow')
    assert context(a).get('response_flow_unresolved')
    body = document(a).body
    assert '응답 값과 사용처의 연결은 미해석' in body
    assert '응답 처리의 정적 연결' not in body


@pytest.mark.parametrize('source', [
    'function outer(document){' + CLICK + '}',
    'function outer({document}){' + CLICK + '}',
    CLICK.replace('document.addEventListener', 'getRoot().document.addEventListener'),
])
def test_shadowed_or_unknown_registration_receiver_is_not_presented_as_document_event(source):
    a = capture(source)
    assert requests(a)
    assert not context(a).get('registration')


def test_controls_from_other_branch_are_not_joined():
    source = "document.addEventListener('click', e=>{if(flag){e.preventDefault()}else{" + CHAIN + "}})"
    a = capture(source)
    assert context(a)['registration']['event_type'] == 'click'
    assert not context(a).get('event_controls')
    assert requests(a)[0]['control_context'][0]['required_value'] is False
    assert '앞선 이벤트 제어 구문' not in document(a).body


@pytest.mark.parametrize('source', [
    'with(other){' + CHAIN + '}',
    "document.addEventListener('click',e=>{with(other){e.preventDefault();" + CHAIN + '}})',
])
def test_dynamic_with_scope_does_not_establish_global_or_event_parameter_binding(source):
    a = capture(source)
    assert requests(a)
    assert not context(a).get('response_flow')
    assert not context(a).get('event_controls')
    assert '응답 처리의 정적 연결' not in document(a).body


def test_dynamic_destination_keeps_recorded_context_without_inventing_url():
    a = capture(CLICK.replace("fetch('/screen')", 'fetch(destination)'))
    assert requests(a)[0]['destination_url'] is None
    assert context(a)['response_flow']
    assert signal(a['record'])['evidence']['request_contexts']
    assert '응답 처리의 정적 연결' in document(a).body
    assert '/screen' not in document(a).body


@pytest.mark.parametrize('component', ['raw', 'record'])
def test_raw_record_relationship_disagreement_is_rejected(component):
    a = capture(CLICK)
    if component == 'record':
        signal(a['record'])['evidence']['request_contexts'][0]['request_context']['registration']['event_type'] = 'submit'
        a['native'] = None
    else:
        context(a)['registration']['event_type'] = 'submit'
        a['record']['raw_ref']['sha256'] = digest(a['raw'])
        a['native'] = None
    with pytest.raises(ValueError, match='request_context_record_source_mismatch'):
        document(a)


@pytest.mark.parametrize('part', ['registration', 'condition_binding', 'event_controls', 'response_flow'])
def test_source_fragment_forgery_is_rejected_even_when_raw_and_record_match(part):
    a = capture(CLICK)
    ctx = context(a)
    fragment = ctx[part][0] if part == 'event_controls' else ctx[part]['read'] if part == 'response_flow' else ctx[part]
    fragment['source_excerpt'] = 'forged'
    refresh_binding(a)
    with pytest.raises(ValueError, match='request_context_source_mismatch'):
        document(a)


@pytest.mark.parametrize('span', [[-1, 12], [0, 999999], [4, 3], [0, 0], []])
def test_response_chain_invalid_provenance_range_is_rejected(span):
    a = capture(CLICK)
    context(a)['response_flow']['chain_source_range'] = span
    refresh_binding(a)
    with pytest.raises(ValueError, match='request_context|response_flow'):
        document(a)


def test_response_chain_must_contain_request_and_response_fragments():
    a = capture(CLICK)
    # This is a valid source range but contains only the request, not its chain.
    context(a)['response_flow']['chain_source_range'] = list(requests(a)[0]['source_range'])
    refresh_binding(a)
    with pytest.raises(ValueError, match='request_context|response_flow'):
        document(a)


@pytest.mark.parametrize('keep', [[], [0], [0, 2]])
def test_response_flow_without_document_write_must_not_create_write_claim(keep):
    a = capture(CLICK)
    flow = context(a)['response_flow']
    flow['writes'] = [flow['writes'][i] for i in keep]
    refresh_binding(a)
    with pytest.raises(ValueError, match='request_context|response_flow'):
        document(a)


def test_direct_callback_block_does_not_become_an_invented_condition():
    a = capture("document.addEventListener('click',e=>{e.preventDefault();" + CHAIN + "})")
    assert context(a)['event_controls']
    assert requests(a)[0]['control_context'] == []
    fast = build_fast_context([a['record']], {'l3': a['raw']}, native=a['native'])
    fact = next(f for f in fast['details']['facts'] if f['title'] == '요청 구문 1')
    assert '조건 블록' not in fact['plain']['text']


def test_legacy_raw_without_relationships_is_not_reparsed_by_builder(monkeypatch):
    a = capture(CLICK)
    for event in requests(a):
        event.pop('request_context', None)
    refresh_binding(a)
    def forbidden(*args, **kwargs):
        raise AssertionError('Builder reparsed stored source')
    monkeypatch.setattr('L3_SCANNER.parsers.javascript.ast.parse_source', forbidden)
    monkeypatch.setattr('L3_SCANNER.parsers.javascript.request_context.enrich_request_context', forbidden)
    doc = document(a)
    assert '응답 처리의 정적 연결' not in doc.body
    assert '콜백 등록' not in doc.body
    assert_preserved(a, doc)


def test_same_source_range_in_declaration_and_multiple_calls_keeps_occurrences():
    a = capture('function install(){' + CLICK + '}install();install();')
    events = requests(a)
    assert len(events) == 3
    assert len({e['event_id'] for e in events}) == 3
    assert len({tuple(e['source_range']) for e in events}) == 1
    contexts = signal(a['record'])['evidence']['request_contexts']
    assert [e['event_id'] for e in contexts] == [e['event_id'] for e in events]
    assert all(e['request_context']['response_flow'] for e in contexts)
    body = document(a).body
    assert '함수 선언 본문을 정적으로 살핀 발생' in body
    assert body.count('정적으로 연결된 함수 호출 구문: install()') == 2


def test_whole_script_binding_checks_do_not_repeat_for_every_request(monkeypatch):
    # Count the expensive script-wide checks instead of a flaky wall-time bound.
    from L3_SCANNER.parsers.javascript import request_context as producer
    original = producer._binds_or_writes
    script_checks = []
    def counted(tree, name, **kwargs):
        if tree.get('type') == 'Program':
            script_checks.append(name)
        return original(tree, name, **kwargs)
    monkeypatch.setattr(producer, '_binds_or_writes', counted)
    a = capture((CHAIN + ';') * 24)
    assert len(requests(a)) == 24
    assert all(e.get('request_context', {}).get('response_flow') for e in requests(a))
    assert len(script_checks) <= 3, script_checks


def test_empty_public_catalog_is_omitted_but_internal_empty_mapping_and_limits_remain():
    a = capture(CLICK)
    fast = build_fast_context([a['record']], {'l3': a['raw']}, native=a['native'])
    empty = [entry for entry in fast['item_mapping'] if entry['fact_ids'] == []]
    assert empty
    assert '공개 상세에 연결 가능한 항목 이름: []' not in fast['model_body']
    for entry in empty:
        assert '[' + entry['section_title'] + ']' in fast['model_body']
        assert entry['sources'] == []
    assert '[JavaScript 관측·해석 한계]' in fast['model_body']
    assert '함수 인자 또는 콜백 호출의 실제 값이 미확인' in fast['model_body']
    assert any(entry['fact_ids'] for entry in fast['item_mapping'])
    assert '공개 상세에 연결 가능한 항목 이름: ["요청 구문 1"]' in fast['model_body']


def test_actual_fast_stored_context_transport_and_direct_linked_fact():
    from test_fast_result_contract import MemoryStore, call
    from evidence_pipeline.aws_runtime import persist_layer
    from evidence_pipeline.aws_fast_result import persist_context, keys

    a = capture(CLICK)
    store = MemoryStore()
    event = {'job_id': 'review-request-context', 'attempt': 1, 'url': a['input']['original_url']}
    envelope = persist_layer(event, 'l3', a['native'], a['raw'], store)
    refs = {'l3': {**envelope['artifact_refs'], 'raw_sha256': digest(a['raw']), 'record_sha256': digest(envelope)}}
    store.put(f"records/{event['job_id']}/1/final/url-activity.json",
              {'state': 'CONTINUE', 'can_skip_judgment': False})
    output = persist_context(event, store, [envelope['evidence_record']], {'l3': a['raw']}, refs,
                             {'state': 'CONTINUE', 'can_skip_judgment': False})
    fast = store.get(keys(event['job_id'], 1)['context'])
    selected = next(row for row in fast['item_mapping'] if row['item_label'] == '요청 구문 1')
    fixed_response = {'verdict': 'BENIGN', 'summary': '오프라인 전달 검사용 고정 응답입니다.',
                      'reasons': [{'text': '정적 요청 구문이 있습니다.', 'related_items': [{
                          'section_title': selected['section_title'], 'item_label': selected['item_label']}]}],
                      'decision_notes': {'provisional_assessment': None, 'unknown': None, 'follow_up_questions': []}}
    result, messages, _ = call(event, store, output, fixed_response)
    assert messages[0]['messages'][0]['content'] == fast['model_body']
    assert '공개 상세에 연결 가능한 항목 이름: []' not in messages[0]['messages'][0]['content']
    assert any(row['fact_ids'] == [] for row in fast['item_mapping'])
    public = store.get(result['fast_result_key'])
    assert public['details'] == fast['details']
    related = set(public['judgment']['reasons'][0]['related_fact_ids'])
    direct = [f for f in public['details']['facts'] if f['fact_id'] in related]
    assert len(direct) == 1
    for marker in ('click', '#join, .login', 'document.write'):
        assert marker in direct[0]['text']
        assert marker in direct[0]['plain']['text']
    assert '실제 응답 내용이나 문서 변경 성공을 확인한 결과는 아닙니다.' in direct[0]['plain']['text']
