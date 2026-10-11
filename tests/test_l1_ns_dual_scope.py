"""Two NS targets remain distinct through native, record, and model context."""

import sys
import json
from copy import deepcopy
from pathlib import Path

import pytest

from evidence_pipeline.context import build_context
from evidence_pipeline.context_inventory import restore
from evidence_pipeline.records import build_record
from evidence_pipeline.model_context import validate_model_context

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'L1'))
from src import handler  # noqa: E402
from src.common import (InfraRecord, NAME_DNS_A, NAME_DNS_NS,
                        NAME_DNS_NS_REGISTRABLE, NAME_IP_ASN, NAME_RDAP)  # noqa: E402
from src.domain_units import DomainUnits, HOST_DOMAIN  # noqa: E402
from src.records import raw_key  # noqa: E402


def _run(monkeypatch, hostname, *, rdap_nameservers=None, host_ns_values=None, rdap_fields=None):
    domain='example.test'
    units=DomainUnits(HOST_DOMAIN, domain, domain, '일치 없음', 'test-list')
    calls=[]
    monkeypatch.setattr(handler, 'extract_fqdn', lambda url: hostname)
    monkeypatch.setattr(handler, 'compute_domain_units', lambda fqdn: units)

    def dns_query(target, kind):
        calls.append((target,kind))
        name={'A':NAME_DNS_A,'NS':NAME_DNS_NS}[kind]
        values=(['ns2.example.test.','ns1.example.test.'] if target==domain else
                host_ns_values or []) if kind=='NS' else []
        return InfraRecord(name,'응답 수신',{'records':values},{}), {f'{target} {kind}':f'{target} {kind} response'}

    def rdap_query(target):
        result={'nameservers':rdap_nameservers if rdap_nameservers is not None
                else ['NS1.EXAMPLE.TEST','NS2.EXAMPLE.TEST'],**(rdap_fields or {})}
        return (InfraRecord(NAME_RDAP,'응답 수신',result,{}),
                {f'https://rdap.test/domain/{target}':
                 'HTTP/1.1 200 OK\r\n\r\n'+json.dumps(result)})

    monkeypatch.setattr(handler,'query_dns',dns_query)
    monkeypatch.setattr(handler,'query_rdap',rdap_query)
    monkeypatch.setattr(handler,'query_ip_asn',lambda ips:(InfraRecord(NAME_IP_ASN,'Not Queried',
        reason='DNS가 IP를 주지 않아 물을 대상이 없음'),{}))
    native,raw=handler.run(f'https://{hostname}/','job','1')
    return native,raw,calls


def test_distinct_host_and_registration_ns_round_trip(monkeypatch):
    native,raw,calls=_run(monkeypatch,'shop.example.test')
    rows={row['name']:row for row in native['인프라결과_목록']}
    assert len(rows)==5
    assert ('shop.example.test','AAAA') not in calls
    assert calls.count(('shop.example.test','NS'))==1
    assert calls.count(('example.test','NS'))==1
    assert rows[NAME_DNS_NS]['observation']['query_target']=='shop.example.test'
    assert rows[NAME_DNS_NS_REGISTRABLE]['observation']['query_target']=='example.test'
    assert native['ns_registration_comparison']['same_set'] is True
    assert raw[NAME_DNS_NS_REGISTRABLE]=={'example.test NS':'example.test NS response'}
    assert raw_key('job','1',NAME_DNS_NS_REGISTRABLE).endswith('/dns_ns_registrable.json')

    record=build_record('l1',native,request_id='job',attempt='1',raw=raw)
    assert len(record['signals'])==5
    assert record['analysis_facts'][0]['same_set'] is True
    assert record['analysis_facts'][0]['source_evidence_ids']==['l1:2','l1:4']
    audit={}
    context=restore(build_context([record],{'l1':raw},audit=audit))
    checks={row['kind']:row['facts'] for row in context['evidence']}
    assert context['layer_subjects']['l1']=={
        'lookup_host':'shop.example.test','registered_domain':'example.test'}
    assert 'dns_ns_host' not in checks
    assert any(item['reason']=='routine_host_ns_nodata_excluded_from_model_context'
               for item in audit['model_omissions'])
    assert 'dns_ns_registration' not in checks
    assert 'rdap' not in checks
    relation=checks['dns_rdap_ns_comparison']
    assert relation=={'status':'matched'}
    model_text=json.dumps(context,ensure_ascii=False)
    assert NAME_DNS_NS_REGISTRABLE not in model_text
    assert 'ns2.example.test' not in model_text
    assert 'NS1.EXAMPLE.TEST' not in model_text
    assert any(item['reason']=='registration_ns_reserved_for_comparison_not_model_lookup'
               for item in audit['model_omissions'])


def test_equal_targets_query_ns_once_and_missing_rdap_ns_is_not_mismatch(monkeypatch):
    native,raw,calls=_run(monkeypatch,'example.test',rdap_nameservers=[])
    assert calls.count(('example.test','NS'))==1
    assert NAME_DNS_NS_REGISTRABLE not in [row['name'] for row in native['인프라결과_목록']]
    assert NAME_DNS_NS_REGISTRABLE not in raw
    assert 'ns_registration_comparison' not in native
    assert len(native['query_lifecycle'])==4
    record=build_record('l1',native,request_id='job',attempt='1',raw=raw)
    context=restore(build_context([record],{'l1':raw}))
    assert not any(row['kind']=='dns_rdap_ns_comparison'
                   for row in context['evidence'])


def test_equal_targets_reuse_host_ns_for_rdap_comparison(monkeypatch):
    native,raw,calls=_run(monkeypatch,'example.test')
    assert calls.count(('example.test','NS'))==1
    assert native['ns_registration_comparison']['dns_lookup']==NAME_DNS_NS
    assert native['ns_registration_comparison']['same_set'] is True
    record=build_record('l1',native,request_id='job',attempt='1',raw=raw)
    assert record['analysis_facts'][0]['source_evidence_ids']==['l1:1','l1:3']
    context=restore(build_context([record],{'l1':raw}))
    assert not any(row['kind'] in ('dns_ns_host','dns_ns_registration')
                   for row in context['evidence'])
    assert next(row['facts'] for row in context['evidence'] if row['kind']=='dns_rdap_ns_comparison')['status']=='matched'


def test_rdap_registration_profile_keeps_dates_status_and_registrar_without_ns_dump(monkeypatch):
    rdap_fields={'registration':'2026-09-01T00:00:00Z',
                 'expiration':'2027-09-01T00:00:00Z',
                 'last_changed':'2026-09-20T00:00:00Z',
                 'status':['client transfer prohibited','server hold'],
                 'registrar':{'name':'Example Registrar','iana_id':'123'}}
    native,raw,_=_run(monkeypatch,'shop.example.test',rdap_fields=rdap_fields)
    record=build_record('l1',native,request_id='job',attempt='1',raw=raw)
    stored=next(signal for signal in record['signals'] if signal['name']=='RDAP')
    assert stored['evidence']['result']=={
        'nameservers':['NS1.EXAMPLE.TEST','NS2.EXAMPLE.TEST'],**rdap_fields}
    audit={}
    model=restore(build_context([record],{'l1':raw},audit=audit))
    rdap=next(row['facts'] for row in model['evidence']
              if row['kind']=='rdap')
    assert rdap=={'registration':rdap_fields['registration'],
                  'expiration':rdap_fields['expiration'],
                  'last_changed':rdap_fields['last_changed'],
                  'domain_status':rdap_fields['status'],
                  'registrar':rdap_fields['registrar']}
    assert next(row['facts'] for row in model['evidence'] if row['kind']=='dns_rdap_ns_comparison')['status']=='matched'
    assert 'nameservers' in json.dumps(audit['source_context'],ensure_ascii=False)
    assert any(item['reason']=='rdap_record_wrapper_excluded_from_model_context'
               for item in audit['model_omissions'])
    leaked=deepcopy(model)
    next(row['facts'] for row in leaked['evidence']
         if row['kind']=='rdap')['assessment']={'url_verdict':'benign'}
    with pytest.raises(ValueError,match='invalid_l1_model_selection'):
        validate_model_context(leaked)


def test_missing_rdap_ns_does_not_dump_registration_ns_to_model(monkeypatch):
    native,raw,_=_run(monkeypatch,'shop.example.test',rdap_nameservers=[])
    record=build_record('l1',native,request_id='job',attempt='1',raw=raw)
    context=restore(build_context([record],{'l1':raw}))
    assert NAME_DNS_NS_REGISTRABLE in raw
    assert NAME_DNS_NS_REGISTRABLE in {row['name'] for row in record['signals']}
    assert not any(row['kind']=='dns_ns_registration'
                   for row in context['evidence'])
    assert not any(row['kind']=='dns_rdap_ns_comparison'
                   for row in context['evidence'])


def test_distinct_sets_are_recorded_as_technical_difference(monkeypatch):
    native,raw,_=_run(monkeypatch,'shop.example.test',rdap_nameservers=['ns9.example.test'])
    assert native['ns_registration_comparison']['same_set'] is False
    assert 'URL verdict' in native['ns_registration_comparison']['scope']
    record=build_record('l1',native,request_id='job',attempt='1',raw=raw)
    context=restore(build_context([record],{'l1':raw}))
    relation=next(row['facts'] for row in context['evidence'] if row['kind']=='dns_rdap_ns_comparison')
    assert relation['status']=='different'
    assert relation['dns_only']==['ns1.example.test','ns2.example.test']
    assert relation['rdap_only']==['ns9.example.test']


def test_delegated_host_ns_remains_visible_without_becoming_registration_ns(monkeypatch):
    native,raw,_=_run(monkeypatch,'shop.example.test',host_ns_values=['ns.shop.example.test.'])
    record=build_record('l1',native,request_id='job',attempt='1',raw=raw)
    context=restore(build_context([record],{'l1':raw}))
    checks={row['kind']:row['facts'] for row in context['evidence']}
    assert checks['dns_ns_host']=={'nameservers':['ns.shop.example.test.']}
    assert context['layer_subjects']['l1']['lookup_host']=='shop.example.test'
    assert 'dns_ns_registration' not in checks


def test_model_contract_rejects_registration_ns_record_dump(monkeypatch):
    native,raw,_=_run(monkeypatch,'shop.example.test')
    next(row for row in native['인프라결과_목록'] if row['name']==NAME_RDAP)['result']['registrar']='Example Registrar'
    record=build_record('l1',native,request_id='job',attempt='1',raw=raw)
    context=restore(build_context([record],{'l1':raw}))
    rdap_check=next(row['facts'] for row in context['evidence']
                    if row['kind']=='rdap')
    assert rdap_check=={'registrar':'Example Registrar'}
    leaked=deepcopy(context)
    leaked['evidence'].append({'id':'E999','kind':'check','facts':{
        'layer':'l1','name':NAME_DNS_NS_REGISTRABLE,
        'query_target':'example.test','result':{'records':['ns1.example.test.']}}})
    with pytest.raises(ValueError,match='l1_record_wrapper_leaked_to_model_context'):
        validate_model_context(leaked)
    repeated=deepcopy(context)
    rdap=next(row['facts'] for row in repeated['evidence']
              if row['kind']=='rdap')
    rdap['nameservers']=['ns1.example.test']
    with pytest.raises(ValueError,match='rdap_nameservers_duplicated_in_model_context'):
        validate_model_context(repeated)
