"""DNS records retain evidence while the model view selects A and omits AAAA."""
import json
import sys
from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import dns.message
import dns.rrset

from evidence_pipeline.context import build_context
from evidence_pipeline.context_inventory import restore
from evidence_pipeline.records import build_record


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'L1'))
from src.infra import dns as l1_dns  # noqa: E402


def test_dns_answer_keeps_addresses_and_alias_without_ttl_in_record():
    question=dns.message.make_query('www.example.test.', 'A')
    response=dns.message.make_response(question)
    response.answer.append(dns.rrset.from_text('www.example.test.', 120, 'IN', 'CNAME', 'host.example.test.'))
    response.answer.append(dns.rrset.from_text('host.example.test.', 300, 'IN', 'A', '203.0.113.7'))

    answer=SimpleNamespace(rrset=response.answer[1],response=response)
    with patch.object(l1_dns._RESOLVER, 'resolve', return_value=answer):
        record, raw=l1_dns.query_dns('www.example.test.', 'A')

    assert record.result == {'records':['203.0.113.7']}
    assert record.detail['cname_chain'] == ['www.example.test. IN CNAME host.example.test.']
    assert '120 IN CNAME' in raw['www.example.test. A']
    assert '300 IN A' in raw['www.example.test. A']
    stored=build_record('l1',{'전체상태':'완료','인프라결과_목록':[asdict(record)]},
                        request_id='dns-new-record',attempt='1',source_reference='dns-new-record',
                        raw={'DNS A':raw})
    assert stored['signals'][0]['evidence']['result'] == {'records':['203.0.113.7']}
    assert stored['signals'][0]['evidence']['detail']['cname_chain'] == [
        'www.example.test. IN CNAME host.example.test.']
    context=restore(build_context([stored],{'l1':{'DNS A':raw}}))
    check=next(row['facts'] for row in context['evidence'] if row['kind']=='dns_a')
    assert check['cname_relations'] == [
        {'from_domain':'www.example.test.','to_domain':'host.example.test.'}]
    assert 'cname_chain' not in check
    assert 'observed_at' not in check
    assert stored['signals'][0]['evidence']['detail']['observed_at']


def test_builder_omits_ttl_from_preexisting_l1_record():
    raw={'DNS A':{'www.example.test. A':'saved response text'}}
    native={'전체상태':'완료','인프라결과_목록':[{
        'name':'DNS A','status':'응답 수신',
        'result':{'records':['203.0.113.7'],'ttl':300},
        'detail':{'cname_chain':['www.example.test. 120 IN CNAME host.example.test.']},
        'observation':{'state':'observed','limitations':[],
                       'query_target':'www.example.test.'}}]}
    record=build_record('l1',native,request_id='dns-with-ttl',attempt='1',
                        source_reference='dns-with-ttl',raw=raw)
    audit={}
    context=restore(build_context([record],{'l1':raw},audit=audit))
    check=next(row['facts'] for row in context['evidence'] if row['kind']=='dns_a')

    assert 'ttl' not in json.dumps(context)
    assert check['ipv4'] == ['203.0.113.7']
    assert check['cname_relations'] == [
        {'from_domain':'www.example.test.','to_domain':'host.example.test.'}]
    assert 'cname_chain' not in check
    assert record['signals'][0]['evidence']['result']['ttl'] == 300
    assert audit['source_context']['observations'][0]['evidence']['result']['ttl'] == 300

    no_alias=deepcopy(record)
    no_alias['signals'][0]['evidence']['detail']['cname_chain']=[]
    context=restore(build_context([no_alias],{'l1':raw}))
    check=next(row['facts'] for row in context['evidence'] if row['kind']=='dns_a')
    assert 'cname_relations' not in check


def test_builder_omits_aaaa_result_but_preserves_record_and_raw():
    target='www.example.test.'
    observation={'state':'observed','limitations':[],'query_target':target}
    chain=['www.example.test. 120 IN CNAME host.example.test.']
    native={'전체상태':'완료','인프라결과_목록':[
        {'name':'DNS A','status':'응답 수신','result':{'records':['203.0.113.7'],'ttl':300},
         'detail':{'cname_chain':chain},'observation':deepcopy(observation)},
        {'name':'DNS AAAA','status':'응답 수신','result':{'records':['2001:db8::7']},
         'detail':{'cname_chain':chain},'observation':deepcopy(observation)},
    ]}
    raw={'DNS A':{},'DNS AAAA':{}}
    record=build_record('l1',native,request_id='dns-two',attempt='1',
                        source_reference='dns-two',raw=raw)
    audit={}
    context=restore(build_context([record],{'l1':raw},audit=audit))
    checks={row['kind']:row['facts'] for row in context['evidence']}

    assert set(checks)=={'dns_a'}
    assert context['layer_subjects']['l1']['lookup_host']==target
    assert 'query_target' not in checks['dns_a']
    assert checks['dns_a']['cname_relations']==[
        {'from_domain':target,'to_domain':'host.example.test.'}]
    assert checks['dns_a']['ipv4']==['203.0.113.7']
    assert 'DNS AAAA' not in json.dumps(context,ensure_ascii=False)
    assert '2001:db8::7' not in json.dumps(context,ensure_ascii=False)
    assert audit['source_context']['observations'][0]['evidence']['result']['ttl']==300
    assert audit['source_context']['observations'][1]['evidence']['result']['records']==['2001:db8::7']
    assert record['signals'][1]['name']=='DNS AAAA'
    assert any(item['source']=='/observations/1' for item in audit['model_omissions'])


def test_builder_omits_aaaa_failure_and_its_exclusive_limit():
    native={'전체상태':'완료','query_lifecycle':[
        {'name':'DNS A','state':'result_recorded','result_status':'응답 수신',
         'raw_response_recorded':False,'run_stop_reason':None},
        {'name':'DNS AAAA','state':'result_recorded','result_status':'도구 오류',
         'raw_response_recorded':False,'run_stop_reason':None}],
        '인프라결과_목록':[
        {'name':'DNS A','status':'응답 수신','result':{'records':['203.0.113.7']},
         'observation':{'state':'observed','limitations':[],'query_target':'a.example.test.'}},
        {'name':'DNS AAAA','status':'도구 오류','reason':'database is locked',
         'observation':{'state':'unavailable','limitations':[],'query_target':'b.example.test.'}},
    ]}
    raw={'DNS A':{},'DNS AAAA':{}}
    record=build_record('l1',native,request_id='dns-different',attempt='1',
                        source_reference='dns-different',raw=raw)
    audit={}
    context=restore(build_context([record],{'l1':raw},audit=audit))
    checks={row['kind']:row['facts'] for row in context['evidence']}

    assert set(checks)=={'dns_a'}
    assert context['layer_subjects']['l1']['lookup_host']=='a.example.test.'
    assert 'query_target' not in checks['dns_a']
    assert all(row['kind']!='limitation' for row in context['evidence'])
    assert 'DNS AAAA' not in json.dumps(context,ensure_ascii=False)
    assert 'database is locked' not in json.dumps(context,ensure_ascii=False)
    assert not any(row['kind']=='coverage' for row in context['evidence'])
    assert all(key not in json.dumps(context) for key in
               ('query_lifecycle','execution','acquisition','analysis'))
    assert audit['source_context']['layers'][0]['coverage']['query_lifecycle'][1]['name']=='DNS AAAA'
    assert any(item['reason']=='dns_aaaa_excluded_from_model_context' for item in audit['model_omissions'])
