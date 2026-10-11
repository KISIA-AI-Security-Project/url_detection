"""A-only L1 selection survives native, stored record and final model projection."""

import json
import sys
from pathlib import Path

import dns.message
import dns.rrset
import pytest

from evidence_pipeline.context import build_context
from evidence_pipeline.context_inventory import restore
from evidence_pipeline.l1_context import ADDRESS_SELECTION
from evidence_pipeline.records import build_record

sys.path.insert(0,str(Path(__file__).resolve().parents[1] / 'L1'))
from src import handler  # noqa: E402
from src.common import InfraRecord, NAME_DNS_A, NAME_DNS_NS, NAME_IP_ASN, NAME_RDAP  # noqa: E402
from src.domain_units import DomainUnits, HOST_DOMAIN  # noqa: E402


@pytest.mark.parametrize('second_observed',[False,True])
def test_first_two_unique_ipv4_and_partial_asn_are_paired_in_model(monkeypatch,second_observed):
    host='shop.example.test'
    addresses=['192.0.2.1','192.0.2.1','192.0.2.2','192.0.2.3']
    selected=[]
    calls=[]
    monkeypatch.setattr(handler,'extract_fqdn',lambda _url:host)
    monkeypatch.setattr(handler,'compute_domain_units',lambda _host:
        DomainUnits(HOST_DOMAIN,'example.test','example.test','일치 없음','test-list'))

    def query_dns(target,kind):
        calls.append((target,kind))
        response=dns.message.make_response(dns.message.make_query(target,kind))
        if kind=='A':
            response.answer.append(dns.rrset.from_text_list(target,300,'IN','A',addresses))
            result={'records':addresses}
        else:
            result={'records':[]}
        return InfraRecord(NAME_DNS_A if kind=='A' else NAME_DNS_NS,'응답 수신',result,{}),{
            f'{target} {kind}':response.to_text()}

    def query_asn(ips):
        selected.extend(ips)
        result={'192.0.2.1':{
            'asn':'64500','prefix':'192.0.2.0/24','country':'ZZ','org':'Example ASN'}}
        detail={'query_targets':list(ips)}
        if second_observed:
            result['192.0.2.2']=dict(result['192.0.2.1'])
        else:
            detail.update({'dropped':{'192.0.2.2':'origin lookup timed out'},
                'failure_occurrences':[{'code':'infrastructure_origin_failed',
                    'occurrence_id':'l1:origin:192.0.2.2','stage':'ip_asn_origin',
                    'impact_scope':'acquisition','target':'192.0.2.2',
                    'reason':'origin lookup timed out'}]})
        return InfraRecord(NAME_IP_ASN,'응답 수신',result,detail),{}

    monkeypatch.setattr(handler,'query_dns',query_dns)
    monkeypatch.setattr(handler,'query_ip_asn',query_asn)
    monkeypatch.setattr(handler,'query_rdap',lambda _target:
        (InfraRecord(NAME_RDAP,'응답 수신',{'nameservers':[]},{}),{}))
    native,raw=handler.run(f'https://{host}/','job','1')
    assert selected==['192.0.2.1','192.0.2.2']
    assert all(kind!='AAAA' for _,kind in calls)
    assert 'DNS AAAA' not in raw
    assert 'DNS AAAA' not in json.dumps(native,ensure_ascii=False)
    rows={row['name']:row for row in native['인프라결과_목록']}
    assert rows[NAME_DNS_A]['result']['records']==addresses
    assert rows[NAME_IP_ASN]['detail']['query_targets']==selected
    assert 'skipped_count' not in json.dumps(native,ensure_ascii=False)

    record=build_record('l1',native,request_id='job',attempt='1',raw=raw)
    assert record['signals'][0]['evidence']['result']['records']==addresses
    assert record['signals'][3]['evidence']['detail']['query_targets']==selected
    audit={}
    model=restore(build_context([record],{'l1':raw},audit=audit))
    checks={row['kind']:row['facts'] for row in model['evidence']}
    assert 'ip_asn' not in checks
    assert 'dns_a' not in checks
    assert model['layer_subjects']['l1']=={
        'lookup_host':host,'registered_domain':'example.test'}
    networks=([
        {'ipv4':['192.0.2.1','192.0.2.2'],'asn':'64500',
         'prefix':'192.0.2.0/24','org':'Example ASN'}]
        if second_observed else [
        {'ipv4':['192.0.2.1'],'asn':'64500',
         'prefix':'192.0.2.0/24','org':'Example ASN'},
        {'ipv4':['192.0.2.2'],'ip_asn':'not_observed'}])
    assert checks['dns_a_ip_asn']=={
        'address_selection':ADDRESS_SELECTION,
        'networks':networks}
    assert 'country' not in json.dumps(model,ensure_ascii=False)
    assert 'country' in json.dumps(record,ensure_ascii=False)
    assert '192.0.2.3' not in json.dumps(model,ensure_ascii=False)
    assert '192.0.2.3' in json.dumps(audit['source_context'],ensure_ascii=False)


def test_negative_a_keeps_unqueried_ip_asn_only_in_record():
    native={'전체상태':'완료','도메인단위':{'호스트 종류':'도메인'},
            'target':{'original_url':'https://example.test/'},
            '인프라결과_목록':[
                {'name':'DNS A','status':'응답 수신','result':'NXDOMAIN'},
                {'name':'IP·ASN','status':'Not Queried',
                 'reason':'DNS가 IP를 주지 않아 물을 대상이 없음'}]}
    record=build_record('l1',native,request_id='job',attempt='1',raw={})
    assert [item['name'] for item in record['signals']]==['DNS A','IP·ASN']
    model=restore(build_context([record],{'l1':{}}))
    assert [(row['kind'],row['facts']) for row in model['evidence']]==[
        ('dns_a',{'response':'NXDOMAIN'})]
