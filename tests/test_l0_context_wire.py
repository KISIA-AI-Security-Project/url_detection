"""Same-input L0 storage -> Builder -> captured Messages request, fully offline."""
from copy import deepcopy
from hashlib import sha256
import json
import pytest

from l0.registry import analyze
from evidence_pipeline import build_context
from evidence_pipeline.aws_runtime import VERSION, persist_layer, load_existing_layer, record_key
from evidence_pipeline.aws_judgment_v2 import JudgmentV2Gateway, judgment_v2
from evidence_pipeline.context_inventory import restore
from evidence_pipeline.judgment_view_v2 import build_judgment_view_v2, validate_judgment_view_v2
from evidence_pipeline.pipeline import render_context
from evidence_pipeline.records import canonical, digest


URL = ('https://user:pass@www.example.net:8443/a/../download/report.pdf.exe'
       '?file=guide.pdf&file=report.doc.exe&return=https%3A%2F%2Fother.example.org%2Flogin#section')


class LocalStore:
    def __init__(self):
        self.values = {}

    def put(self, key, value, exclusive=False):
        if exclusive and key in self.values:
            raise AssertionError('duplicate write')
        self.values[key] = canonical(value)

    def put_bytes(self, key, value, exclusive=False):
        if exclusive and key in self.values:
            raise AssertionError('duplicate write')
        self.values[key] = bytes(value)

    def get(self, key, optional=False):
        if optional and key not in self.values:
            return None
        return json.loads(self.values[key])


def capture_l0_request(url=URL, *, include_store=False):
    native = analyze(url)
    native_before = deepcopy(native)
    store = LocalStore()
    event = {'job_id': 'l0-context-wire', 'attempt': 1, 'url': url}
    envelope = persist_layer(event, 'l0', native, native['raw_evidence'], store)
    loaded = load_existing_layer(event, 'l0', store)
    assert loaded == envelope
    record = loaded['evidence_record']
    raw = store.get(envelope['artifact_refs']['raw'])
    audit = {}
    context = build_context([record], {'l0': raw}, audit=audit)
    # A controlled activity fixture only supplies the adapter's mandatory binding.
    # No DNS, HTTP, AWS, or actual model call takes place in this verification.
    activity = {'request_id': event['job_id'], 'attempt': '1', 'input_url': url,
                'state': 'DNS_UNKNOWN', 'can_skip_judgment': False}
    activity_key = 'records/l0-context-wire/1/final/url-activity.json'
    context['url_activity_observation'] = {
        'state': 'DNS_UNKNOWN', 'reason': 'offline_fixture',
        'scope': 'controlled_adapter_fixture_not_network_observation',
    }
    context_sha = sha256(render_context(context).encode()).hexdigest()
    key = record_key(event['job_id'], '1', 'final')
    final = {'integration_version': VERSION, 'job_id': event['job_id'], 'attempt': 1,
             'input_url': url, 'analysis_status': 'COMPLETED', 'model_context': context,
             'model_context_sha256': context_sha, 'url_activity_key': activity_key,
             'url_activity_sha256': digest(activity),
             'coverage': {'l0': {name: record[name] for name in ('execution', 'acquisition', 'analysis')}}}
    store.put(activity_key, activity)
    store.put_bytes(key, json.dumps(final, ensure_ascii=False, separators=(',', ':')).encode())
    captured = []
    expected_view = build_judgment_view_v2(context)

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, size=-1):
            return json.dumps({'stop_reason': 'end_turn', 'content': [{
                'type': 'text', 'text': json.dumps({
                    'verdict': 'UNKNOWN', 'interpretation_text': '오프라인 전송 형식 확인용 응답이다.',
                    'basis_fact_id_1': expected_view['fact_units'][0]['id'],
                }, ensure_ascii=False)}]}, ensure_ascii=False).encode()

    def factory(view):
        assert view == expected_view

        def opener(request, **kwargs):
            captured.append(bytes(request.data))
            return Response()

        return JudgmentV2Gateway('https://example.net', 'offline-test-key', 'offline-test-model',
                                 view=view, opener=opener, max_tokens=500, timeout=5)

    output = judgment_v2({**event, 'context_key': key, 'context_sha256': context_sha}, store, factory)
    prefix = 'judgments/l0-context-wire/1/v2/'
    request = store.get(prefix + 'request.json')
    wire_view = json.loads(request['messages'][0]['content'])
    assert len(captured) == 1 and captured[0] == store.values[prefix + 'request.json']
    assert wire_view == expected_view == store.get(prefix + 'view.json')
    assert audit['source_context']['l0_url_observations'] == {'raw': raw, 'record': record}
    assert native == native_before and record['signals'] == native['observations']
    assert wire_view['requested_urls'] == [url]
    artifacts = {'native': native, 'raw': raw, 'record': record, 'audit': audit,
            'model_context': context, 'final_model_document': wire_view, 'request': request,
            'audit_view': expected_view, 'mock_adapter_result': output}
    if include_store:
        artifacts['_store'] = store
    return artifacts


def test_l0_same_input_stored_evidence_reaches_actual_messages_body():
    artifacts = capture_l0_request()
    view = artifacts['final_model_document']
    selected = [row['facts'] for row in view['fact_units'] if row['kind'] == 'url_observation']
    doubles = next(row for row in selected if row['검사'] == '이중_확장자')
    assert len(doubles['관찰']) == 2
    assert [value['검사한_문자열'] for value in doubles['관찰']] == ['report.pdf.exe', 'report.doc.exe']
    assert doubles['관찰'][1]['값_순번'] == 1
    guidance = view['layer_boundaries']['reading_guide']['l0']['추가 판단 안내']
    assert set(guidance) == {'DGA_패턴', '타이포스쿼팅', '단축_서비스_목록_일치', '무료_발급_도메인'}
    assert '이중_확장자' not in guidance
    assert 'analysis_status' not in json.dumps(selected)
    assert 'reference_versions' not in json.dumps(selected)
    assert '목록_버전' not in json.dumps(selected, ensure_ascii=False)
    assert view['fact_units'] == artifacts['audit_view']['fact_units']


def test_no_positive_records_still_sends_subject_and_all_review_instructions():
    artifacts = capture_l0_request('https://www.example.net/')
    view = artifacts['final_model_document']
    assert [row['kind'] for row in view['fact_units']] == ['url_subject']
    assert set(view['layer_boundaries']['reading_guide']['l0']['추가 판단 안내']) == {
        'DGA_패턴', '타이포스쿼팅', '단축_서비스_목록_일치', '무료_발급_도메인', '이중_확장자'}
    assert artifacts['record']['signals'] == []


@pytest.mark.parametrize('change', ['metadata', 'guidance'])
def test_final_judgment_document_rejects_metadata_or_guidance_reintroduced_after_builder(change):
    view = capture_l0_request()['audit_view']
    if change == 'metadata':
        row = next(row for row in view['fact_units'] if row['kind'] == 'url_observation')
        row['facts']['관찰'][0]['errors'] = [{'code': 'must-not-reenter-model'}]
        # Accounting is consistent: rejection must be due to the L0 selection rule.
        view['source_accounting']['source_evidence_sha256'] = digest(view['fact_units'])
    else:
        view['layer_boundaries']['reading_guide']['l0']['추가 판단 안내']['이중_확장자'] = 'unexpected'
    with pytest.raises(ValueError, match='l0_'):
        validate_judgment_view_v2(view)


if __name__ == '__main__':
    from pathlib import Path
    import sys
    destination = Path(sys.argv[1]).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    for name, url in [('observed', URL), ('no-records', 'https://www.example.net/')]:
        folder = destination / name
        folder.mkdir(exist_ok=True)
        for kind, value in capture_l0_request(url).items():
            (folder / (kind + '.json')).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print('Saved offline raw/native/record/audit/final document/actual captured request for 2 inputs.')
