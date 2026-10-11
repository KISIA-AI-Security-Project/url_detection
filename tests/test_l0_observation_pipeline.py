"""Positive URL observations survive record normalization and local storage."""
from copy import deepcopy
import json

import pytest

from l0.parsing import parse_url_stage
from evidence_pipeline.records import build_record,canonical,digest
from evidence_pipeline.record_contract import validate_record


GUIDANCE={
    'DGA_패턴':'도메인 문자열이 DGA 패턴에 해당하는지 다른 관찰과 함께 판단한다.',
    '타이포스쿼팅':'도메인 문자열이 브랜드·서비스 이름의 오타나 유사 표기를 이용한 타이포스쿼팅인지 판단한다.',
}


def native(url='https://example.com/',observations=(),errors=()):
    raw=parse_url_stage(url).to_dict()['raw_evidence']
    execution=({'state':'run','check_count':10,'record_count':len(observations)} if raw['parse_status']=='SUCCESS'
               else {'state':'not_run','reason':'url_parse_not_successful','parse_status':raw['parse_status']})
    return {'producer_contract':'url-observations-3','raw_evidence':raw,
        'observations':deepcopy(list(observations)),'errors':deepcopy(list(errors)),
        'analysis_execution':execution,'judgment_guidance':deepcopy(GUIDANCE),
        'reference_versions':{'test':'offline-1'}}


def observation(index=0):
    return {'검사':'쿼리의_외부_주소',
        '관찰':{'쿼리_항목':'next','값_순번':index,'쿼리_값':'https://receiver.example.net/'},
        '판단에 쓸 점':'사이트가 이 값을 이동 주소로 사용한다면 외부 사이트로 유도할 수 있으므로 실제 처리 방식과 함께 판단한다.'}


def through(result):
    original=deepcopy(result)
    record=build_record('l0',result,request_id='private-id',attempt=1)
    validate_record(record)
    assert result==original
    return record


def test_success_without_positive_records_is_completed_and_retains_guidance_metadata():
    result=native()
    record=through(result)
    assert record['signals']==[] and record['errors']==[]
    assert record['record_contract_version']=='l0-observations-1'
    assert record['execution']['state']=='completed'
    assert record['acquisition']['state']=='observed'
    assert record['analysis']['state']=='completed'
    assert record['coverage']['judgment_guidance']==GUIDANCE
    assert record['coverage']['producer_contract']=='url-observations-3'


def test_each_compact_record_and_duplicate_occurrence_is_preserved():
    # Equal values at different positions remain separate recorded occurrences.
    positives=[observation(0),observation(1),observation(1)]
    record=through(native('https://example.com/?next=https://receiver.example.net/',positives))
    assert record['signals']==positives
    assert len(record['signals'])==len(positives)
    assert all(set(signal)=={'검사','관찰','판단에 쓸 점'} for signal in record['signals'])


@pytest.mark.parametrize('positives',[[],[observation()]])
def test_analysis_failure_stays_separate_from_positive_records(positives):
    errors=[{'code':'url_observation_failed','stage':'url_observation','impact_scope':'analysis',
        'target':{'check':'IDN_문자_변환','label':label},'occurrence_id':f'idn:{index}'}
        for index,label in enumerate(('first','second'))]
    record=through(native(observations=positives,errors=errors))
    assert record['analysis']['state']=='partial'
    assert record['execution']['state']=='completed'
    assert record['acquisition']['state']=='observed'
    assert record['signals']==positives
    assert record['errors']==errors
    assert len({error['target']['label'] for error in record['errors']})==2


@pytest.mark.parametrize('url',['','http://[invalid'])
def test_invalid_input_records_analysis_not_performed(url):
    record=through(native(url))
    assert record['signals']==[] and record['errors']
    assert record['analysis']['state']=='not_performed'
    assert record['execution']['state']=='completed'
    assert record['acquisition']['state']=='observed'


def test_query_parser_failure_does_not_hide_valid_positive_or_make_a_negative_record():
    result=native('https://example.com/?bad=%E7&next=https://receiver.example.net/',[observation()])
    record=through(result)
    assert result['raw_evidence']['query_errors']
    assert record['analysis']['state']=='partial'
    assert any(error['code']=='query_component_parse_failed' for error in record['errors'])
    assert record['signals']==result['observations']


@pytest.mark.parametrize('mutation',[
    lambda value:value.update(producer_contract='url-observations-999'),
    lambda value:value['analysis_execution'].update(record_count=10),
    lambda value:value['observations'].append({'검사':'incomplete'}),
    lambda value:value.update(evaluations=[]),
    lambda value:value.pop('judgment_guidance'),
])
def test_declared_observation_contract_does_not_fall_back_to_legacy(mutation):
    result=native()
    mutation(result)
    with pytest.raises(ValueError):build_record('l0',result,request_id='r',attempt=1)


def test_legacy_aggregate_and_v2_evaluations_remain_readable():
    legacy={'analysis_records':[{'analysis_record':{'name':'old','status':'해당없음','value':None}}]}
    assert build_record('l0',legacy,request_id='r',attempt=1)['signals'][0]['legacy_status']=='해당없음'
    old=native()
    for key in ('observations','errors','judgment_guidance','reference_versions'):old.pop(key)
    old['producer_contract']='url-evaluations-2'
    old['evaluations']=[{'name':'old-evaluation','predicate':{'statement':'old condition','result':'not_matched'},
        'applicability':{'state':'applicable','reason':None},
        'interpretation':{'certainty':'technical_observation_only','url_verdict':'not_assessed','limits':'Old scope'},
        'scope':'URL string','facts':{'original':'preserved'},'limitations':[],'reference_versions':{}}]
    record=through(old)
    assert record['signals'][0]['evidence']=={'original':'preserved'}


def test_raw_and_compact_observations_round_trip_in_storage_without_key_loss(tmp_path):
    from evidence_pipeline.aws_runtime import persist_layer,load_existing_layer
    result=native('https://example.com/?request_id=keep&script_id=keep2&evidence_ref=E99999&sha256=keep3',
        [observation(0),observation(1)])
    class LocalStore:
        def put(self,key,value):
            path=tmp_path/key
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(canonical(value))
        def get(self,key,optional=False):
            path=tmp_path/key
            return json.loads(path.read_text(encoding='utf-8')) if path.exists() else None
    store=LocalStore()
    event={'job_id':'l0-storage','attempt':1,'url':result['raw_evidence']['raw_url']}
    envelope=persist_layer(event,'l0',result,result['raw_evidence'],store)
    assert load_existing_layer(event,'l0',store)==envelope
    raw_path=tmp_path/envelope['artifact_refs']['raw']
    record_path=tmp_path/envelope['artifact_refs']['record']
    saved_raw=json.loads(raw_path.read_text(encoding='utf-8'))
    saved_envelope=json.loads(record_path.read_text(encoding='utf-8'))
    saved_record=saved_envelope['evidence_record']
    validate_record(saved_record)
    assert saved_raw==result['raw_evidence']
    assert 'query' not in saved_raw
    assert saved_raw['parsed']['search']=='?request_id=keep&script_id=keep2&evidence_ref=E99999&sha256=keep3'
    assert saved_record['raw_ref']['sha256']==digest(saved_raw)
    assert saved_record['signals']==result['observations']
    assert saved_record['coverage']['reference_versions']==result['reference_versions']
    assert saved_record['coverage']['judgment_guidance']==GUIDANCE
    assert saved_envelope['observation']==result


def test_normalizer_cannot_bind_observations_to_different_raw_input():
    result=native(observations=[observation()])
    wrong_raw=deepcopy(result['raw_evidence'])
    wrong_raw['raw_url']='https://other.example.net/'
    with pytest.raises(ValueError,match='l0_raw_input_mismatch'):
        build_record('l0',result,request_id='r',attempt=1,raw=wrong_raw)


@pytest.mark.parametrize('mutation',[
    lambda record:record['coverage']['analysis_execution'].update(record_count=99),
    lambda record:record['signals'][0].update(name='different check'),
    lambda record:record['signals'][0].pop('판단에 쓸 점'),
])
def test_stored_compact_record_damage_is_rejected(mutation):
    record=through(native(observations=[observation()]))
    mutation(record)
    with pytest.raises(ValueError):validate_record(record)


@pytest.mark.parametrize('url',[
    'https://example.com/',
    'https://example.com/?next=https://receiver.example.net/&next=https://other.example.org/',
    'https://example.com/?bad=%E7&next=https://receiver.example.net/',
    '',
])
def test_real_l0_producer_preserves_its_compact_records_and_raw_binding(url):
    from l0.registry import analyze
    result=analyze(url)
    record=through(result)
    assert result['producer_contract']=='url-observations-3'
    assert record['signals']==result['observations']
    assert record['raw_ref']['sha256']==digest(result['raw_evidence'])
    assert record['coverage']['judgment_guidance']==result['judgment_guidance']
    if not url:assert record['analysis']['state']=='not_performed'
    elif result['raw_evidence']['query_errors']:assert record['analysis']['state']=='partial'
    else:assert record['analysis']['state']=='completed'
