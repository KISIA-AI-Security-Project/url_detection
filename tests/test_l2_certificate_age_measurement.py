"""C01의 임계값 없는 측정을 raw → 생산 → 저장 재조회 → Messages까지 대조한다."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import socket

import pytest

from l2_scanner import scanner
from l2_scanner.analyzers.certificate import certificate_age, ct_first_seen
from l2_scanner.collectors import certificate_collector
from evidence_pipeline import build_context, build_record
from evidence_pipeline.aws_runtime import persist_layer, load_existing_layer
from evidence_pipeline.aws_judgment_v2 import JudgmentV2Gateway, PROMPT
from evidence_pipeline.judgment_view_v2 import build_judgment_view_v2
from evidence_pipeline.record_contract import validate_record
from evidence_pipeline.context_inventory import restore
from evidence_pipeline.l2_context import AGE_LABEL, TIME_LABEL, C01_MISSING, C01_FAILED, TLS_MISSING


NOW = datetime(2026, 9, 18, 12, 14, 57, tzinfo=timezone.utc)
URL = 'https://example.com/'


class FixedClock(datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW if tz is None else NOW.astimezone(tz)


class StoredJSON:
    def __init__(self):
        self.values = {}

    def put(self, key, value, exclusive=False):
        assert not exclusive or key not in self.values
        self.values[key] = json.dumps(value)

    def get(self, key, optional=False):
        if optional and key not in self.values:
            return None
        return json.loads(self.values[key])


def capture_measurement(monkeypatch, days=15, *, missing=False, invalid=False,
                        missing_start=False, tls_failure=False, http_failure=False,
                        scan_finished_at=None):
    def no_network(*args, **kwargs):
        raise AssertionError('This verification must stay offline')
    monkeypatch.setattr(socket, 'create_connection', no_network)
    monkeypatch.setattr(socket, 'getaddrinfo', no_network)
    monkeypatch.setattr(certificate_age, 'datetime', FixedClock)
    monkeypatch.setattr(ct_first_seen, 'datetime', FixedClock)
    start = 'invalid-date' if invalid else (NOW - timedelta(days=days)).isoformat()
    tls = {'hostname': 'example.com', 'tls_version': 'TLSv1.3',
           'leaf_certificate': None if missing else {'not_before': start, 'fingerprint': 'offline', 'sct_timestamps': []},
           'certificate_chain': [], 'chain_valid': None, 'chain_error': None, 'errors': []}
    if missing_start:
        tls['leaf_certificate'].pop('not_before')
    ct = {'first_seen': (NOW - timedelta(days=45)).isoformat(),
          'source': 'offline_fixture', 'sct_count': 0, 'log_entries': 1, 'errors': []}
    http = {'original_url': URL, 'final_url': URL, 'current_url': URL, 'status_code': 200,
            'redirect_chain': [], 'headers': {}, 'response_body': {'body_complete': True},
            'download': {}, 'errors': []}
    if http_failure:
        http.update(final_url=None, status_code=None,
                    errors=[{'stage': 'http', 'code': 'connection_failed', 'error': 'offline HTTP failure'}])
    if tls_failure:
        def failed_handshake(*args, **kwargs):
            raise TimeoutError('offline TLS timeout')
        monkeypatch.setattr(certificate_collector, '_handshake', failed_handshake)
    else:
        monkeypatch.setattr(scanner, 'collect_certificate', lambda *args: deepcopy(tls))
    monkeypatch.setattr(scanner, 'collect_ct', lambda *args: deepcopy(ct))
    monkeypatch.setattr(scanner, 'etld1', lambda value: 'example.com')
    monkeypatch.setattr(scanner, '_now_iso', lambda: scan_finished_at or NOW.isoformat())
    # 이 입력에서는 C01 측정과 기존 C06의 저장·전달만 확인한다.
    monkeypatch.setattr(scanner, 'HEADER_ANALYZERS', [])
    monkeypatch.setattr(scanner, 'CERTIFICATE_ANALYZERS', [certificate_age])
    monkeypatch.setattr(scanner, 'CERTIFICATE_ANALYZERS_EXTENDED', [])
    native = scanner._scan_collected(http, NOW.isoformat())
    original = deepcopy(native)
    store = StoredJSON()
    event = {'job_id': 'c01-measurement', 'attempt': 1, 'url': URL}
    envelope = persist_layer(event, 'l2', native, native['raw'], store)
    loaded = load_existing_layer(event, 'l2', store)
    assert loaded == envelope and native == original
    record = loaded['evidence_record']
    raw = store.get(envelope['artifact_refs']['raw'])
    audit = {}
    context = build_context([record], {'l2': raw}, audit=audit)
    view = build_judgment_view_v2(context)
    sent = []
    def opener(request, **kwargs):
        sent.append(json.loads(request.data))
        return io.BytesIO(json.dumps({'stop_reason': 'end_turn', 'content': [{'type': 'text',
            'text': json.dumps({'verdict': 'UNKNOWN', 'interpretation_text': 'Offline fixture',
                                'basis_fact_id_1': view['fact_units'][0]['id']})}]}).encode())
    gateway = JudgmentV2Gateway('https://example.net', 'offline-key', 'offline-model', view=view, opener=opener)
    gateway(PROMPT, json.dumps(view))
    wire = json.loads(sent[0]['messages'][0]['content'])
    assert wire == view
    return {'native': native, 'raw': raw, 'record': record, 'audit': audit, 'builder-document': restore(context),
            'model-document': wire, 'messages-request': sent[0]}


@pytest.mark.parametrize('days', [2, 15, 29, 30, 31, 45, 365, -3])
def test_measurement_preserves_values_in_saved_record_and_final_wire(monkeypatch, days):
    artifacts = capture_measurement(monkeypatch, days)
    native = artifacts['native']['signals'][0]
    record = artifacts['record']['signals'][0]
    model = next(row['facts'] for row in artifacts['model-document']['fact_units']
                 if row['kind'] == 'certificate_age')
    assert record['state'] == 'observed' and record['cause_ids'] == []
    assert record['assessment']['predicate'] == {
        'statement': 'Whole elapsed days from certificate notBefore to measured_at',
        'result': 'relationship_only'}
    for result in (native, record):
        assert result['measurement_state'] == 'observed'
        assert result['evidence'] == native['evidence']
        assert result['evidence']['age_days'] == days
        assert 'detected' not in result and 'detected' not in result.get('not_recorded', [])
        assert 'fresh' not in result['evidence']
        assert 'within configured freshness threshold' not in json.dumps(result)
        assert 'within the configured freshness threshold' not in json.dumps(result)
    assert model[AGE_LABEL] == f'{days}일' + (' (유효기간 시작 전; 시간차를 24시간 단위로 내림한 값)' if days < 0 else '')
    assert model[TIME_LABEL] == native['evidence']['measured_at']
    assert set(model) == {AGE_LABEL, TIME_LABEL, 'certificate_ref'}
    assert native['evidence']['not_before'] == artifacts['raw']['tls']['leaf_certificate']['not_before']
    # C06도 승인된 측정 계약을 따르되 C01과 독립된 시각·경과일을 유지한다.
    ct = artifacts['native']['signals'][1]
    assert ct['result_kind'] == 'measurement' and ct['evidence']['age_days'] == 45
    assert 'detected' not in ct and 'fresh' not in ct['evidence']


@pytest.mark.parametrize('invalid', [False, True])
def test_missing_or_invalid_input_remains_unavailable_with_recorded_reason(monkeypatch, invalid):
    artifacts = capture_measurement(monkeypatch, missing=not invalid, invalid=invalid)
    row = artifacts['record']['signals'][0]
    assert row['measurement_state'] == 'unavailable'
    assert row['state'] == 'unresolved' and 'detected' not in row
    codes = {cause['code'] for cause in artifacts['record']['causes']}
    assert ('analyzer_failed' if invalid else 'certificate_not_before_unavailable') in codes
    assert 'analysis_unresolved_reason_not_recorded' not in codes
    rows = artifacts['model-document']['fact_units']
    assert not any(x['kind'] == 'certificate_age' for x in rows)
    limits = [x['facts'] for x in rows if x['kind'] in {'certificate_age_limit', 'tls_observation_limit'}]
    assert len(limits) == 1 and limits[0]['관측 한계'] == (C01_FAILED if invalid else TLS_MISSING)


@pytest.mark.parametrize('mutation', ['detected', 'fresh', 'missing_time', 'missing_age', 'false_state'])
def test_measurement_record_rejects_reintroduced_binary_result(monkeypatch, mutation):
    record = capture_measurement(monkeypatch)['record']
    row = record['signals'][0]
    if mutation == 'detected': row['detected'] = False
    elif mutation == 'fresh': row['evidence']['fresh'] = True
    elif mutation == 'missing_time': row['evidence'].pop('measured_at')
    elif mutation == 'missing_age': row['evidence'].pop('age_days')
    else: row['state'] = 'not_observed_in_analyzed_scope'
    with pytest.raises(ValueError):
        validate_record(record)


def test_legacy_c01_keeps_its_original_meaning():
    legacy = {'signals': [{'id': 'L2-C-01', 'name': 'certificate_age',
                         'detected': True, 'evidence': {'age_days': 15, 'fresh': True}}]}
    result = build_record('l2', legacy, request_id='historical', attempt=1)
    assert result['signals'][0]['detected'] is True
    assert result['signals'][0]['evidence'] == legacy['signals'][0]['evidence']
    assert 'freshness threshold' in result['signals'][0]['assessment']['predicate']['statement']


if __name__ == '__main__':
    output = Path(__file__).resolve().parents[2] / 'results' / 'c01-no-threshold-20260928'
    output.mkdir(parents=True, exist_ok=True)
    with pytest.MonkeyPatch.context() as patch:
        artifacts = capture_measurement(patch)
    for name, value in artifacts.items():
        (output / (name + '.json')).write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
    print('Saved offline C01 raw, native, reloaded record and captured Messages request.')
