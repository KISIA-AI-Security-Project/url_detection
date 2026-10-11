"""Approved L0/L1 facts keep their meaning without a model-facing ref graph."""
from copy import deepcopy
import json
from pathlib import Path
import socket

import pytest

from l0.registry import analyze
from evidence_pipeline import build_context, build_record
from evidence_pipeline.context_inventory import restore
from evidence_pipeline.l01_text import render_l0, render_l1
from evidence_pipeline.l1_context import ADDRESS_SELECTION


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError('Text rendering must not access the network')
    monkeypatch.setattr(socket, 'create_connection', blocked)
    monkeypatch.setattr(socket.socket, 'connect', blocked)


def body(blocks):
    return '\n\n'.join('[' + block.title + ']\n' + '\n'.join(block.lines) for block in blocks)


def l0_source(url):
    native = analyze(url)
    record = build_record('l0', native, request_id='text', attempt=1)
    return restore(build_context([record], {'l0': native['raw_evidence']}))


def l1_source(*items, host='google.com', domain='google.com'):
    return {'evidence': [{'id': f'E{index}', 'kind': kind, 'facts': facts}
                         for index, (kind, facts) in enumerate(items, 1)],
            'layer_subjects': {'l1': {k: v for k, v in
                [('lookup_host', host), ('registered_domain', domain)] if v}},
            'reading_guide': {}}


def test_l0_original_values_occurrences_and_guidance_are_not_reinterpreted():
    url = ('https://user@example.net/report.pdf.exe?f=guide.pdf.exe&f=guide.pdf.exe'
           '&errors=https%3A%2F%2Fother.example.org%2F%3Fsha256%3Dkeep')
    source = l0_source(url)
    before = deepcopy(source)
    blocks = render_l0(source)
    text = body(blocks)
    assert source == before
    assert url in text
    for row in source['evidence']:
        if row['kind'] == 'url_observation':
            assert row['facts']['판단에 쓸 점'] in text
    assert '정상적인 사이트 URL이라면 username이 붙지 않는다.' in text
    double = next(block for block in blocks if block.title == '이중_확장자')
    assert '\n'.join(double.lines).count('검사한_문자열: guide.pdf.exe') == 2
    assert '값_순번: 0' in text and '값_순번: 1' in text
    assert 'https://other.example.org/?sha256=keep' in text
    assert '검토 지시이며 관측 사실이나 목록 불일치 결과가 아니다.' in text
    assert 'requested_url_index' not in text and 'evidence_ref' not in text
    assert {row['id'] for row in source['evidence']} <= {eid for block in blocks for eid in block.evidence_ids}


def test_l0_shared_subject_reference_is_resolved_without_removing_occurrence():
    source = l0_source('https://bit.ly/path')
    subject = next(row for row in source['evidence'] if row['kind'] == 'url_subject')
    observation = next(row for row in source['evidence'] if row['kind'] == 'url_observation')
    observation['facts']['관찰'] = [{'공통 대상': {'evidence_ref': subject['id']}},
                                  {'공통 대상': {'evidence_ref': subject['id']}}]
    block = next(block for block in render_l0(source) if block.title == observation['facts']['검사'])
    text = '\n'.join(block.lines)
    assert '관찰 1:' in text and '관찰 2:' in text
    assert text.count('접속 호스트: bit.ly') == 2
    assert 'evidence_ref' not in text


def test_l0_unparsed_input_does_not_become_a_claim_that_no_issue_exists():
    source = l0_source('http://[invalid')
    blocks = render_l0(source)
    text = body(blocks)
    assert '원본 URL: http://[invalid' in text
    assert '안전' not in text and '관찰 없음' not in text
    assert [block.title for block in blocks] == ['L0 URL 문자열 관찰', 'L0 추가 판단 안내']


def test_l0_unresolved_common_subject_fails_instead_of_printing_internal_ref():
    source = l0_source('https://bit.ly/path')
    observation = next(row for row in source['evidence'] if row['kind'] == 'url_observation')
    observation['facts']['관찰'] = [{'공통 대상': {'evidence_ref': 'E999'}}]
    with pytest.raises(ValueError, match='unresolved_l0_text_subject'):
        render_l0(source)


def google_source():
    return l1_source(
        ('dns_a_ip_asn', {'address_selection': ADDRESS_SELECTION, 'networks': [{
            'ipv4': ['142.251.15.138', '142.251.15.101'], 'asn': '15169',
            'prefix': '142.251.15.0/24', 'org': 'GOOGLE - Google LLC, US'}]}),
        ('dns_rdap_ns_comparison', {'status': 'matched'}),
        ('rdap', {'registration': '1997-09-15T04:00:00Z', 'expiration': '2028-09-14T04:00:00Z',
                  'last_changed': '2019-09-09T15:39:04Z',
                  'registrar': {'name': 'MarkMonitor Inc.', 'iana_id': '292'},
                  'domain_status': ['client delete prohibited', 'client transfer prohibited',
                    'client update prohibited', 'server delete prohibited',
                    'server transfer prohibited', 'server update prohibited']}))


def test_google_approved_projection_is_readable_with_network_group_and_ns_relation():
    source = google_source()
    before = deepcopy(source)
    text = body(render_l1(source))
    assert source == before
    assert '조회 호스트와 등록 도메인: google.com' in text
    assert 'IP: 142.251.15.138, 142.251.15.101' in text
    assert text.count('ASN: 15169') == 1
    assert '등록 도메인 google.com의 DNS NS 목록과 RDAP에 등록된 NS 목록이 일치한다.' in text
    assert '등록대행사 IANA ID: 292' in text
    for value in source['evidence'][2]['facts']['domain_status']:
        assert value in text
    assert 'NS1' not in text and 'evidence_ref' not in text and 'E1' not in text
    assert 'https://google.com' not in text  # Missing original URL stays missing.


@pytest.mark.parametrize('reply', [{'response': 'SERVFAIL'}, {'response': 'REFUSED'},
                                 {'response': 'NXDOMAIN'}, {'response_codes': ['SERVFAIL', 'REFUSED']}])
def test_registration_ns_received_failure_keeps_codes_and_same_domain_rdap_names(reply):
    source = l1_source(('dns_ns_registration', reply),
                       ('rdap', {'nameservers': ['NS1.GOOGLE.COM', 'NS2.GOOGLE.COM']}))
    blocks = render_l1(source)
    ns = next(block for block in blocks if block.title == 'DNS NS · RDAP NS 대조')
    text = '\n'.join(ns.lines)
    for code in reply.get('response_codes', [reply.get('response')]):
        assert code in text
    assert '비교할 수 없다.' in text and 'NS1.GOOGLE.COM' in text
    assert '불일치' not in text and '안전' not in text
    assert ns.evidence_ids == ('E1', 'E2')
    assert body(blocks).count('NS1.GOOGLE.COM') == 1


def test_partial_asn_and_missing_organization_are_scoped_to_each_ip():
    source = l1_source(('dns_a_ip_asn', {'address_selection': ADDRESS_SELECTION, 'networks': [
        {'ipv4': ['192.0.2.1'], 'asn': '64500', 'prefix': '192.0.2.0/24', 'org': 'not_observed'},
        {'ipv4': ['192.0.2.2'], 'ip_asn': 'not_observed'}]}))
    text = body(render_l1(source))
    first, second = text.split('IP: 192.0.2.2')
    assert 'ASN: 64500' in first and '조직 정보는 확보하지 못했다.' in first
    assert 'IP·ASN 정보를 확보하지 못했다.' in second
    assert 'ASN: 64500' not in second and '공통' not in text


def test_distinct_host_and_registration_targets_and_names_are_not_merged():
    source = l1_source(
        ('dns_ns_host', {'nameservers': ['ns.shop.example.test']}),
        ('dns_rdap_ns_comparison', {'status': 'different', 'dns_only': ['ns1.example.test'],
                                  'rdap_only': ['ns2.example.test']}),
        host='shop.example.test', domain='example.test')
    text = body(render_l1(source))
    assert '조회 호스트: shop.example.test' in text
    assert '등록 도메인 example.test의 DNS NS 목록' in text
    assert 'ns.shop.example.test' in text and 'ns1.example.test' in text and 'ns2.example.test' in text


def test_dns_cname_and_literal_ipv6_remain_observed_data():
    source = l1_source(
        ('dns_a', {'response': 'NXDOMAIN', 'cname_relations': [
            {'from_domain': 'shop.example.test.', 'to_domain': 'target.example.test.'}]}),
        ('infrastructure_observation', {'lookup': 'RDAP', 'status': 'not_observed', 'reason': 'budget exhausted'}),
        host='shop.example.test', domain='example.test')
    text = body(render_l1(source))
    assert 'NXDOMAIN' in text and 'target.example.test.' in text and 'budget exhausted' in text
    literal = l1_source(('ip_asn', {'networks': [{'ip': ['2001:db8::1'], 'asn': '64500',
                           'prefix': '2001:db8::/32', 'org': 'Example'}]}),
                        host='2001:db8::1', domain=None)
    literal_text = body(render_l1(literal))
    assert '2001:db8::1' in literal_text and 'DNS A' not in literal_text


def test_unknown_l1_fact_fails_instead_of_silently_omitting():
    source = google_source()
    source['evidence'][0]['facts']['new_observation'] = 'must not disappear'
    with pytest.raises(ValueError, match='invalid_l1_model_selection'):
        render_l1(source)


def test_absent_layers_have_no_empty_blocks():
    assert render_l0({}) == []
    assert render_l1({}) == []


def test_saved_google_record_replays_through_current_selection_without_input_change():
    root = Path(__file__).parents[1] / '.test-cache/live-google-ip-asn-20260928T031949Z'
    if not (root / 'record.json').exists():
        pytest.skip('local saved lookup snapshot absent')
    record = json.loads((root / 'record.json').read_text(encoding='utf-8-sig'))
    raw = json.loads((root / 'raw.json').read_text(encoding='utf-8-sig'))
    before = deepcopy((record, raw))
    source = restore(build_context([record], {'l1': raw}))
    text = body(render_l1(source))
    assert 'IP: 142.251.15.138, 142.251.15.101' in text
    assert '등록 도메인 google.com의 DNS NS 목록과 RDAP에 등록된 NS 목록이 일치한다.' in text
    assert '등록대행사 IANA ID: 292' in text
    assert (record, raw) == before
