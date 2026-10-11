"""Received DNS failures remain visible from producer through Messages input."""
from copy import deepcopy
import io
import json
import socket

import dns.message
import dns.rcode
import dns.resolver
import pytest

from evidence_pipeline import build_context, build_record
from evidence_pipeline.aws_judgment_v2 import JudgmentV2Gateway, PROMPT
from evidence_pipeline.judgment_view_v2 import build_judgment_view_v2
from evidence_pipeline.l1_context import build_l1_context
from test_l1_ns_dual_scope import _run
from src import handler
from src.infra import dns as dns_collector


@pytest.mark.parametrize('hostname', ['example.test', 'shop.example.test'])
@pytest.mark.parametrize('codes', [
    ['SERVFAIL'], ['REFUSED'], ['NXDOMAIN'], ['SERVFAIL', 'REFUSED'],
])
def test_registration_ns_received_failure_reaches_model(monkeypatch, tmp_path, hostname, codes):
    def no_network(*args, **kwargs):
        raise AssertionError('No network calls in the controlled DNS response test')

    monkeypatch.setattr(socket.socket, 'connect', no_network)
    monkeypatch.setattr(socket, 'create_connection', no_network)
    # Install the existing controlled A, host NS, RDAP and IP-ASN queries.
    _run(monkeypatch, hostname)
    saved_query = handler.query_dns
    domain = 'example.test'
    messages = []
    for code in codes:
        response = dns.message.make_response(dns.message.make_query(domain, 'NS'))
        response.set_rcode(dns.rcode.from_text(code))
        messages.append(response)

    def resolve(target, kind):
        assert (target, kind) == (domain, 'NS')
        if codes == ['NXDOMAIN']:
            qname = messages[0].question[0].name
            raise dns.resolver.NXDOMAIN(qnames=[qname], responses={qname: messages[0]})
        raise dns.resolver.NoNameservers(request=dns.message.make_query(domain, 'NS'), errors=[
            (f'192.0.2.{index + 1}', False, 53, code, response)
            for index, (code, response) in enumerate(zip(codes, messages))
        ])

    monkeypatch.setattr(dns_collector._RESOLVER, 'resolve', resolve)
    monkeypatch.setattr(handler, 'query_dns', lambda target, kind:
        dns_collector.query_dns(target, kind) if (target, kind) == (domain, 'NS')
        else saved_query(target, kind))
    native, raw = handler.run(f'https://{hostname}/', 'ns-response', '1')
    name = 'DNS NS' if hostname == domain else 'DNS NS (등록 단위)'
    expected_result = codes[0] if len(codes) == 1 else {'response_codes': codes}
    expected_facts = {'response': codes[0]} if len(codes) == 1 else {'response_codes': codes}
    native_ns = next(row for row in native['인프라결과_목록'] if row['name'] == name)
    assert native_ns['status'] == '응답 수신'
    assert native_ns['result'] == expected_result
    # The producer retains every response code in the same lookup's raw text.
    assert all(f'rcode {code}' in raw[name][f'{domain} NS'] for code in codes)
    assert 'ns_registration_comparison' not in native
    record = build_record('l1', native, raw=raw, request_id='ns-response', attempt='1')
    assert next(row for row in record['signals'] if row['name'] == name)['evidence']['result'] == expected_result
    assert not record['analysis_facts']

    # Read the saved raw and normalized record as the public Builder does.
    for key, value in [('record', record), ('raw', raw)]:
        (tmp_path / f'{key}.json').write_text(json.dumps(value, ensure_ascii=False), encoding='utf-8')
    record = json.loads((tmp_path / 'record.json').read_text(encoding='utf-8'))
    raw = json.loads((tmp_path / 'raw.json').read_text(encoding='utf-8'))
    before = deepcopy((record, raw))
    standalone = build_l1_context(record, raw)
    selected = [row for row in standalone['evidence'] if row['kind'] == 'dns_ns_registration']
    assert len(selected) == 1
    assert {key: value for key, value in selected[0].items() if key not in ('id', 'kind')} == expected_facts
    audit = {}
    context = build_context([record], {'l1': raw}, audit=audit)
    final = build_judgment_view_v2(context)
    captured = []

    def opener(request, **kwargs):
        captured.append(json.loads(request.data))
        return io.BytesIO(b'{"stop_reason":"end_turn","content":[{"type":"text","text":"{}"}]}')

    gateway = JudgmentV2Gateway('https://offline.invalid', 'offline-key', 'offline-model',
                                view=final, opener=opener)
    gateway(PROMPT, json.dumps(final, ensure_ascii=False))
    wire = json.loads(captured[0]['messages'][0]['content'])
    assert wire == final
    assert [row['facts'] for row in wire['fact_units'] if row['kind'] == 'dns_ns_registration'] == [expected_facts]
    assert not any(row['kind'] == 'dns_rdap_ns_comparison' for row in wire['fact_units'])
    assert audit['source_context']['l1_raw'] == raw
    assert (record, raw) == before
