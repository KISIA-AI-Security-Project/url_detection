"""The reviewed layer text is the actual user message, with source mapping external."""
from copy import deepcopy
import io
import json
from pathlib import Path

import pytest

from evidence_pipeline import build_context, build_record
from evidence_pipeline.aws_judgment_v2 import JudgmentV2Gateway, PROMPT
from evidence_pipeline.model_text import (build_text_context, render_text_context,
    prepare_text_messages, call_text_messages, TextContextNotReady)
from test_l2_readable_context import capture_http, HTTP_CASES
from test_l2_c08_context import capture_wildcard, CASES


@pytest.mark.parametrize('case', HTTP_CASES)
def test_http_same_native_record_selected_text_and_captured_messages(monkeypatch, case):
    a = capture_http(monkeypatch, case)
    original = deepcopy((a['raw'], a['native'], a['record']))
    audit = {}
    doc = build_text_context([a['record']], {'l2': a['raw']}, audit=audit)
    calls = []
    def opener(request, **kwargs):
        calls.append(json.loads(request.data))
        return io.BytesIO(b'{"stop_reason":"end_turn","content":[{"type":"text","text":"{}"}]}')
    gateway = JudgmentV2Gateway('https://offline.example', 'offline-key', 'offline-model', view=None, opener=opener)
    assert call_text_messages(doc, gateway, 'Capture only; no URL verdict.') == {}
    assert calls[0]['messages'][0]['content'] == doc.body
    assert original == (a['raw'], a['native'], a['record'])
    assert audit['selection']['source_context']
    for entry in doc.source_map:
        assert doc.body[entry['start']:entry['end']].startswith('[' + entry['title'] + ']')
    assert not any(token in doc.body for token in ('evidence_ref', 'requested_url_index',
        'body_complete', 'body_truncated', 'response_observation', 'source_evidence_ids'))
    if case == 'destination_failure':
        assert 'HTTPS→HTTP 이동 지시: 관측됨' in doc.body
        assert 'HTTP 응답: 응답을 받지 못함' in doc.body
        assert '콘텐츠 유형 대조' not in doc.body
    if case == 'roundtrip':
        assert doc.body.count('URL: https://a.example.com/report.pdf') == 3  # request plus two occurrences
        assert '경로의 3번째 주소' in doc.body
    if case == 'two_failures':
        assert doc.body.count('이유: same message') == 2
    if case == 'refresh_target':
        assert '이 지시에 따른 이동은 수행하지 않음' in doc.body
        assert '이동 대상: https://a.example.com/next' in doc.body


@pytest.mark.parametrize('case', CASES)
def test_certificate_facts_share_tls_block_without_exposed_ids(monkeypatch, case):
    a = capture_wildcard(monkeypatch, case)
    doc = build_text_context([a['record']], {'l2': a['raw']})
    assert not any(token in doc.body for token in ('certificate_ref', 'tls_scope', 'tls_target',
        'tls_version', 'wildcard_names', 'san_count', 'evidence_ref'))
    if case == 'wildcard_match':
        tls = next(b for b in doc.blocks if b.title == 'L2 TLS 접속과 인증서')
        assert '일치한 인증서 이름: *.example.com' in '\n'.join(tls.lines)
    if case == 'wildcard_mismatch':
        assert '불일치 (SAN 기준)' in doc.body and '*.example.com' in doc.body
    if case == 'shared_c03':
        tls = next(b for b in doc.blocks if b.title == 'L2 TLS 접속과 인증서')
        assert 'offline C08 analysis failed' in '\n'.join(tls.lines)


def test_old_id_prompt_cannot_be_sent_with_new_text(monkeypatch):
    a = capture_http(monkeypatch)
    doc = build_text_context([a['record']], {'l2': a['raw']})
    def blocked(*args, **kwargs):
        raise AssertionError('no call may occur')
    gateway = JudgmentV2Gateway('https://offline.example', 'offline-key', 'offline-model', view=None, opener=blocked)
    with pytest.raises(TextContextNotReady, match='legacy_id_response_prompt'):
        call_text_messages(doc, gateway, PROMPT)


def test_l3_is_not_silently_omitted_or_json_dumped():
    native = {'scan': {'status': 'completed'}, 'signals': [], 'errors': []}
    raw = {'html': {'parse_succeeded': False}, 'javascript': {}}
    record = build_record('l3', native, request_id='unreviewed', attempt=1, raw=raw)
    selected = build_context([record], {'l3': raw})
    with pytest.raises(TextContextNotReady, match='l3_or_unreviewed'):
        render_text_context(selected)


def capture_l012(monkeypatch):
    """One URL, controlled collectors and actual L0/L1/L2 producer/store paths."""
    from l0.registry import analyze
    from src import handler
    from src.common import InfraRecord
    from src.domain_units import DomainUnits, HOST_DOMAIN
    from evidence_pipeline.aws_runtime import persist_layer, load_existing_layer
    from test_l0_context_wire import LocalStore
    # Actual HTTP collection/analyzers with the existing offline transport.
    a = capture_http(monkeypatch, 'type_mismatch')
    url = a['record']['target']['original_url']
    host, domain = 'a.example.com', 'example.com'
    monkeypatch.setattr(handler, 'extract_fqdn', lambda _: host)
    monkeypatch.setattr(handler, 'compute_domain_units', lambda _: DomainUnits(HOST_DOMAIN, domain, domain, '일치 없음', 'offline-list'))
    def dns(target, kind):
        values = ['192.0.2.10', '192.0.2.11'] if kind == 'A' else ['ns1.example.com.'] if target == domain else []
        return InfraRecord('DNS ' + kind, '응답 수신', {'records': values}, {}), {f'{target} {kind}': 'controlled response'}
    monkeypatch.setattr(handler, 'query_dns', dns)
    rdap = {'nameservers': ['NS1.EXAMPLE.COM'], 'registration': '2020-01-01T00:00:00Z',
            'expiration': '2027-01-01T00:00:00Z', 'registrar': {'name': 'Example Registrar', 'iana_id': '123'}}
    monkeypatch.setattr(handler, 'query_rdap', lambda target: (InfraRecord('RDAP', '응답 수신', rdap, {}),
        {'https://rdap.example/domain/' + target: json.dumps(rdap)}))
    def asn(ips):
        result = {ip: {'asn': '64500', 'prefix': '192.0.2.0/24', 'org': 'Example Network'} for ip in ips}
        return InfraRecord('IP·ASN', '응답 수신', result, {'query_targets': list(ips)}), {ip: json.dumps(value) for ip, value in result.items()}
    monkeypatch.setattr(handler, 'query_ip_asn', asn)
    n0 = analyze(url)
    n1, r1 = handler.run(url, 'text-l012', '1')
    store, event = LocalStore(), {'job_id': 'text-l012', 'attempt': 1, 'url': url}
    records, raws, artifacts = [], {}, {}
    for layer, native, raw in [('l0', n0, n0['raw_evidence']), ('l1', n1, r1), ('l2', a['native'], a['raw'])]:
        original = deepcopy((native, raw))
        envelope = persist_layer(event, layer, native, raw, store)
        loaded = load_existing_layer(event, layer, store)
        assert envelope == loaded and original == (native, raw)
        records.append(loaded['evidence_record'])
        raws[layer] = store.get(envelope['artifact_refs']['raw'])
        artifacts['native-' + layer] = native
    return records, raws, artifacts


def test_l012_same_url_pipeline_combines_reviewed_sections(monkeypatch):
    records, raws, artifacts = capture_l012(monkeypatch)
    assert len({record['target']['original_url'] for record in records}) == 1
    document = build_text_context(records, raws)
    assert '[L0 URL 문자열 관찰]' in document.body
    assert '[L1 인프라 조회]' in document.body
    assert '[L2 HTTP 관측]' in document.body
    assert 'ASN: 64500' in document.body
    assert '유형 대조: 불일치' in document.body
    assert 'L3' not in document.body
