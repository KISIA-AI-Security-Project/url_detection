"""Literal data -> native -> record -> actual model text and public detail."""
from copy import deepcopy

import pytest

from evidence_pipeline.fast_context import build_fast_context
from test_l3_javascript_text import capture, document, assert_preserved


def test_related_content_and_button_destination_reach_model_and_public_fact():
    source = '''window.pageData={data:[{content:[
        {type:"title",content:"Account Team"},
        {type:"button",text:"CONTINUE",url:"https://destination.example/step"}
    ]}]};'''
    a = capture(source, html='<title>Account notice</title>')
    fact = next(f for f in a['record']['analysis_facts'] if f['kind'] == 'static_literal_content_data')
    assert fact['declarations'] == a['raw']['javascript']['static_data']
    doc = document(a, combined=True)
    assert '문구 선언 /data/0/content/0/content: Account Team' in doc.body
    assert '문구 선언 /data/0/content/1/text: CONTINUE' in doc.body
    assert '주소 선언 /data/0/content/1/url: https://destination.example/step' in doc.body
    assert '데이터 항목 /data/0/content/1의 type 선언: button' in doc.body
    assert '실제로 이동함' not in doc.body
    assert_preserved(a, doc)
    context = build_fast_context([a['record']], {'l3': a['raw']}, native=a['native'])
    public = [f for f in context['details']['facts'] if 'Account Team' in f['text']]
    assert len(public) == 1
    assert 'CONTINUE' in public[0]['plain']['text']
    assert 'destination.example' in public[0]['plain']['text']


def test_unrelated_array_items_keep_their_paths_and_no_target_is_invented():
    a = capture('const content=[{title:"First",url:"/one"},{title:"Second",url:"/two"}];')
    doc = document(a)
    assert '문구 선언 /0/title: First' in doc.body
    assert '주소 선언 /1/url: /two' in doc.body
    assert 'https://page.example.com/two' in doc.body
    assert '동작을 실행함' not in doc.body


def test_json_data_is_retained_while_script_code_and_conditional_writes_are_not_evaluated():
    a = capture(scripts=[{'script_id': 'data', 'type': 'inline', 'media_type': 'application/json',
                         'source': '{"title":"Article","url":"https://news.example/article"}'},
                        {'script_id': 'code', 'type': 'inline',
                         'source': 'if (flag) { window.data={title:"Hidden",url:"/hidden"}; }'}])
    doc = document(a)
    assert 'Article' in doc.body and 'news.example/article' in doc.body
    assert 'Hidden' not in doc.body
    assert a['raw']['javascript']['static_data'][0]['declaration_kind'] == 'json_data_block'


def test_pure_configuration_stays_in_record_without_model_inventory():
    a = capture('const config={endpoint:"https://telemetry.example",retry:2};')
    doc = document(a)
    assert a['record']['analysis_facts']
    assert 'telemetry.example' not in doc.body
    assert '[코드에 선언된 콘텐츠 데이터]' not in doc.body
    assert any('literal configuration' in item['reason'] for item in doc.source_context['model_omissions'])


def test_record_must_match_the_native_data_declaration():
    a = capture('const data={title:"Article",url:"/article"};')
    altered = deepcopy(a['record'])
    next(f for f in altered['analysis_facts'] if f['kind'] == 'static_literal_content_data')['declarations'][0]['value']['title'] = 'Other'
    with pytest.raises(ValueError, match='javascript_static_data_record_source_mismatch'):
        build_fast_context([altered], {'l3': a['raw']})


def test_labels_and_layout_configuration_do_not_become_content_facts():
    a = capture('const config={networks:{one:{title:"Social name"}},responsive:{wide:{label:"Wide screen"}},post:{title:"Post title"}};')
    doc = document(a)
    assert a['record']['analysis_facts']
    assert 'Social name' not in doc.body and 'Wide screen' not in doc.body
    assert '[코드에 선언된 콘텐츠 데이터]' not in doc.body
    assert any('without a text/address relationship' in r['reason'] for r in doc.source_context['model_omissions'])


def test_same_host_menu_inventory_is_omitted_but_controls_and_other_targets_remain():
    a = capture('''const header={navItems:[
      {title:"Product menu",url:"/products"},
      {title:"External information",url:"https://other.example/info"},
      {type:"button",text:"CONTINUE",url:"/step"},
      {button_text:"NEXT STEP",action_url:"/next"}]};''',
      html='<a href="/home">Homepage</a>')
    doc = document(a, combined=True)
    assert 'Product menu' not in doc.body
    assert 'External information' in doc.body and 'https://other.example/info' in doc.body
    assert 'CONTINUE' in doc.body and 'https://page.example.com/step' in doc.body
    assert 'NEXT STEP' in doc.body and 'https://page.example.com/next' in doc.body
    assert a['raw']['javascript']['static_data'][0]['value']['navItems'][0]['title'] == 'Product menu'
    assert_preserved(a, doc)


def test_unknown_menu_target_is_not_treated_as_same_host():
    a = capture('const header={navItems:[{title:"Unresolved",url:"javascript:chooseTarget()"}]};',
                html='<a href="/home">Homepage</a>')
    doc = document(a)
    assert 'Unresolved' in doc.body and 'javascript:chooseTarget()' in doc.body
