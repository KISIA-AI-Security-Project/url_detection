"""Offline L0 producer -> record -> final model document selection checks."""
from copy import deepcopy
import socket
from urllib.parse import quote

import pytest

from l0.registry import analyze
from evidence_pipeline import build_context, build_record
from evidence_pipeline.context_inventory import restore
from evidence_pipeline.judgment_view_v2 import build_judgment_view_v2
from evidence_pipeline.model_context import validate_model_context


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError('L0 context checks must not access the network')
    monkeypatch.setattr(socket, 'create_connection', blocked)
    monkeypatch.setattr(socket.socket, 'connect', blocked)
    monkeypatch.setattr(socket.socket, 'connect_ex', blocked)


def project(url, native=None):
    native = analyze(url) if native is None else native
    raw = native['raw_evidence']
    before_native = deepcopy(native)
    record = build_record('l0', native, request_id='l0-private-request', attempt=1)
    before_record = deepcopy(record)
    audit = {}
    context = build_context([record], {'l0': raw}, audit=audit)
    view = restore(context)
    judgment = build_judgment_view_v2(context)
    assert native == before_native
    assert record == before_record
    assert audit['source_context']['l0_url_observations'] == {'raw': raw, 'record': record}
    assert judgment['fact_units'] == view['evidence']
    assert judgment['requested_urls'] == view['requested_urls'] == [url]
    assert judgment['layer_boundaries']['reading_guide'] == view['reading_guide']
    assert validate_model_context(context) == [r['id'] for r in view['evidence']]
    return native, record, view, judgment, audit


def rows(view, kind):
    return [r for r in view['evidence'] if r['kind'] == kind]


def guidance(view):
    return view['reading_guide']['l0']['추가 판단 안내']


def keys(value):
    if isinstance(value, dict):
        return set(value).union(*(keys(v) for v in value.values()))
    if isinstance(value, list):
        return set().union(*(keys(v) for v in value))
    return set()


def dereference(source, pointer):
    value = source
    for key in pointer.strip('/').split('/'):
        value = value[int(key)] if isinstance(value, list) else value[key]
    return value


def test_real_producer_repeated_positions_and_groups_survive_to_final_document():
    url = ('https://user@brand-login.brand-login.com.net.example.com/report.pdf.exe?'
           + '&'.join('f=guide.pdf.exe' for _ in range(12))
           + '&next=https://other.example.org/&next=https://other.example.org/')
    native, record, view, judgment, audit = project(url)
    assert len(record['signals']) > 10  # Ten check types do not cap occurrences.
    subject = rows(view, 'url_subject')[0]
    assert subject['facts'] == {
        '원본 URL': {'requested_url_index': 0},
        '접속 호스트': 'brand-login.brand-login.com.net.example.com',
        '등록 도메인': 'example.com',
        '서브도메인': 'brand-login.brand-login.com.net',
    }
    grouped = rows(view, 'url_observation')
    expected_groups = {(s['검사'], s['판단에 쓸 점']) for s in record['signals']}
    assert len(grouped) == len(expected_groups)
    assert sum(len(r['facts']['관찰']) for r in grouped) == len(record['signals'])
    double = next(r for r in grouped if r['facts']['검사'] == '이중_확장자')
    assert len(double['facts']['관찰']) == 13
    assert double['facts']['관찰'][0]['위치'] == 'URL 경로의 마지막 부분'
    assert [o['값_순번'] for o in double['facts']['관찰'][1:]] == list(range(12))
    assert [o['검사한_문자열'] for o in double['facts']['관찰'][1:]] == ['guide.pdf.exe'] * 12
    external = next(r for r in grouped if r['facts']['검사'] == '쿼리의_외부_주소')
    assert [o['값_순번'] for o in external['facts']['관찰']] == [0, 1]
    assert all(o['값에_들어_있는_호스트'] == 'other.example.org' for o in external['facts']['관찰'])
    split = next(r for r in grouped if r['facts']['검사'] == '호스트_단어_분리')
    assert [o['부분_순번'] for o in split['facts']['관찰']] == [0, 1]
    for row in grouped:
        pointers = audit['evidence_mapping'][row['id']]['source_pointers']
        assert len(pointers) == len(row['facts']['관찰'])
        source_signals = [dereference(audit['source_context'], p) for p in pointers]
        assert source_signals == [s for s in record['signals'] if
            (s['검사'], s['판단에 쓸 점']) == (row['facts']['검사'], row['facts']['판단에 쓸 점'])]
        for observed in row['facts']['관찰']:
            assert not {'호스트', 'URL_호스트', '실제_접속_호스트',
                        '등록_도메인', '실제_등록_도메인', 'URL의_등록_도메인'} & set(observed)
    assert all(x['represented_by'] == subject['id'] for x in audit['deduplicated_values'])
    assert record['signals'] == native['observations']
    assert judgment['layer_boundaries']['coverage_fact_ids_by_layer'] == {}


def test_equal_source_occurrences_are_not_deduplicated_and_distinct_hints_stay_distinct():
    url = 'https://example.com/report.pdf.exe'
    native = analyze(url)
    first = next(s for s in native['observations'] if s['검사'] == '이중_확장자')
    native['observations'].append(deepcopy(first))
    different_hint = deepcopy(first)
    different_hint['판단에 쓸 점'] = '별도 제공된 해석 안내를 보존한다.'
    native['observations'].append(different_hint)
    native['analysis_execution']['record_count'] = len(native['observations'])
    _, _, view, _, audit = project(url, native)
    grouped = rows(view, 'url_observation')
    assert len(grouped) == 2
    assert [len(r['facts']['관찰']) for r in grouped] == [2, 1]
    assert grouped[0]['facts']['관찰'][0] == grouped[0]['facts']['관찰'][1]
    assert len(audit['evidence_mapping'][grouped[0]['id']]['source_pointers']) == 2


@pytest.mark.parametrize('url', [
    'data:image/png;base64,' + 'A' * 2048,
    'https://example.com/?file=' + quote('data:image/png;base64,' + 'A' * 2048 + '.pdf.exe', safe=''),
])
def test_long_data_image_url_strings_stay_verbatim_in_raw_record_audit_and_model(url):
    native, record, view, _, audit = project(url)
    assert view['requested_urls'][0] == native['raw_evidence']['raw_url'] == url
    assert 'embedded_image_reference' not in keys(audit['source_context']['l0_url_observations'])
    assert 'embedded_image_reference' not in keys(view)
    if record['signals']:
        source_value = record['signals'][0]['관찰']['검사한_문자열']
        assert source_value.startswith('data:image/') and len(source_value) > 2048
        assert rows(view, 'url_observation')[0]['facts']['관찰'][0]['검사한_문자열'] == source_value


@pytest.mark.parametrize('url', ['', 'http://[invalid'])
def test_unparsed_url_is_referenced_without_new_analysis_or_status_output(url, monkeypatch):
    native = analyze(url)
    def forbidden(*args, **kwargs):
        raise AssertionError('Builder must not parse the URL again')
    monkeypatch.setattr('l0.parsing.parse_url_stage', forbidden)
    monkeypatch.setattr('l0.registry.analyze', forbidden)
    _, record, view, _, audit = project(url, native)
    assert rows(view, 'url_subject')[0]['facts'] == {'원본 URL': {'requested_url_index': 0}}
    assert rows(view, 'url_observation') == []
    assert record['errors'] and record['analysis']['state'] == 'not_performed'
    assert 'errors' not in keys(view) and 'analysis' not in keys(view)
    assert audit['source_context']['l0_url_observations']['record']['errors'] == record['errors']


@pytest.mark.parametrize('url,present', [
    ('https://example.com/', set()),
    ('https://bit.ly/path', {'단축_서비스_목록_일치'}),
    ('https://user.github.io/', {'무료_발급_도메인'}),
    ('https://example.com/report.pdf.exe', {'이중_확장자'}),
    ('https://bit.ly/report.pdf.exe', {'단축_서비스_목록_일치', '이중_확장자'}),
    ('https://user.github.io/report.pdf.exe', {'무료_발급_도메인', '이중_확장자'}),
])
def test_additional_guidance_depends_on_each_observation_kind_independently(url, present):
    _, record, view, _, _ = project(url)
    conditional = {'단축_서비스_목록_일치', '무료_발급_도메인', '이중_확장자'}
    assert {s['검사'] for s in record['signals']} & conditional == present
    assert set(guidance(view)) == {'DGA_패턴', '타이포스쿼팅'} | (conditional - present)
    assert not any('TLD' in name for name in guidance(view))
    assert all(not any(word in text for word in ('목록에 없다', '불일치한다', '안전하다'))
               for text in guidance(view).values())


def test_state_error_reference_version_and_storage_metadata_remain_audit_only():
    _, record, view, judgment, audit = project('https://bit.ly/?bad=%E7')
    assert record['errors'] and record['analysis']['state'] == 'partial'
    assert record['coverage']['reference_versions']
    assert any('목록_버전' in s['관찰'] for s in record['signals'])
    forbidden = {'errors', 'analysis', 'analysis_status', 'execution', 'acquisition',
                 'query_status', 'parse_status', 'reference_versions', '목록_버전',
                 'raw_ref', 'request_id', 'attempt', 'producer_contract', 'record_contract_version'}
    assert not keys(view) & forbidden
    assert not keys(judgment['fact_units']) & forbidden
    assert audit['source_context']['l0_url_observations']['record'] == record
    assert any(o['reason'] == 'l0_reference_version_is_audit_only' for o in audit['model_omissions'])


def test_metadata_named_query_parameters_and_values_remain_observed_url_data():
    destination = 'https://other.example.org/?analysis=completed&errors=none&request_id=keep&sha256=keep'
    url = 'https://example.com/?errors=' + quote(destination, safe='')
    _, record, view, _, _ = project(url)
    source = next(s for s in record['signals'] if s['검사'] == '쿼리의_외부_주소')
    observed = next(r for r in rows(view, 'url_observation') if r['facts']['검사'] == '쿼리의_외부_주소')['facts']['관찰'][0]
    assert observed['쿼리_항목'] == source['관찰']['쿼리_항목'] == 'errors'
    assert observed['쿼리_값'] == source['관찰']['쿼리_값'] == destination


def test_different_unicode_host_display_is_not_removed_as_an_exact_subject_duplicate():
    _, record, view, _, _ = project('https://xn--pple-43d.com/')
    subject = rows(view, 'url_subject')[0]['facts']
    source = next(s for s in record['signals'] if s['검사'] == 'IDN_문자_변환')
    observed = next(r for r in rows(view, 'url_observation') if r['facts']['검사'] == 'IDN_문자_변환')['facts']['관찰'][0]
    assert subject['접속 호스트'] == 'xn--pple-43d.com'
    assert observed == source['관찰']
    assert observed['실제_접속_호스트'] != subject['접속 호스트']
    assert observed['비교용_표기'] == 'apple.com'


@pytest.mark.parametrize('index', [True, False, -1, 1, 999])
def test_validator_rejects_invalid_requested_url_indices(index):
    _, _, view, _, _ = project('https://example.com/')
    rows(view, 'url_subject')[0]['facts']['원본 URL']['requested_url_index'] = index
    with pytest.raises(ValueError, match='invalid_l0_requested_url_reference'):
        validate_model_context(view)


@pytest.mark.parametrize('case', [
    'subject_metadata', 'row_metadata', 'observed_list_version',
    'extra_coverage', 'empty_observation_list', 'empty_observation_object',
    'duplicated_host', 'duplicated_group', 'missing_always_hint',
    'wrong_conditional_hint', 'extra_tld_hint', 'wrong_subject_ref',
    'observed_execution_metadata', 'observed_error_metadata',
])
def test_validator_rejects_reintroduced_metadata_empty_facts_and_incorrect_guidance(case):
    _, _, view, _, _ = project('https://user@example.com/report.pdf.exe')
    subject = rows(view, 'url_subject')[0]
    observation = rows(view, 'url_observation')[0]
    facts = observation['facts']
    guide = view['reading_guide']['l0']
    if case == 'subject_metadata': subject['facts']['parse_status'] = 'SUCCESS'
    elif case == 'row_metadata': facts['execution'] = {'state': 'completed'}
    elif case == 'observed_list_version': facts['관찰'][0]['목록_버전'] = 'test-list'
    elif case == 'extra_coverage':
        view['evidence'].append({'id': 'E999', 'kind': 'coverage', 'facts': {'layer': 'l0', 'analysis': 'completed'}})
    elif case == 'empty_observation_list': facts['관찰'] = []
    elif case == 'empty_observation_object': facts['관찰'] = [{}]
    elif case == 'duplicated_host': facts['관찰'][0]['호스트'] = subject['facts']['접속 호스트']
    elif case == 'duplicated_group':
        duplicate = deepcopy(observation)
        duplicate['id'] = 'E999'
        view['evidence'].append(duplicate)
    elif case == 'missing_always_hint': guide['추가 판단 안내'].pop('DGA_패턴')
    elif case == 'wrong_conditional_hint': guide['추가 판단 안내']['이중_확장자'] = '확장자 목록에 일치하지 않는다.'
    elif case == 'extra_tld_hint': guide['추가 판단 안내']['TLD'] = '피싱 빈발 여부를 추측한다.'
    elif case == 'wrong_subject_ref': guide['공통 대상'] = {'evidence_ref': observation['id']}
    elif case == 'observed_execution_metadata': facts['관찰'][0]['analysis'] = {'state': 'completed'}
    elif case == 'observed_error_metadata': facts['관찰'][0]['errors'] = [{'code': 'private-error'}]
    with pytest.raises(ValueError):
        validate_model_context(view)
