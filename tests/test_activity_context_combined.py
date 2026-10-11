"""Same native inputs and durable outputs across the two execution layouts."""
from copy import deepcopy
from datetime import datetime, timezone
from threading import Barrier, Lock, current_thread
from urllib.parse import urlsplit

import pytest

from evidence_pipeline import aws_runtime as rt
from L3_SCANNER import scan_content
from L3_SCANNER.policies.operational import operational_detection_policy
from test_fast_result_contract import CASES, MemoryStore
from test_model_text import capture_l012


def prepared(monkeypatch, case):
    records, raws, artifacts = capture_l012(monkeypatch)
    url = records[0]['target']['original_url']
    native = scan_content({'original_url': url, 'document_url': url,
                           'html': {'content': CASES[case][1]}}, operational_detection_policy())
    store = MemoryStore()
    event = {'job_id': 'text-l012', 'attempt': 1, 'url': url, 'layers': {}}
    preflight = {'job_id': event['job_id'], 'attempt': 1, 'input_url': url,
                 'hostname': urlsplit(url).hostname, 'addresses': ['192.0.2.10'],
                 'a_addresses': ['192.0.2.10'], 'aaaa_addresses': [],
                 'state': 'public_target_at_preflight', 'layer_network_started': True,
                 'observed_at': datetime.now(timezone.utc).isoformat()}
    for layer in rt.LAYERS:
        n, raw = (native, native['raw']) if layer == 'l3' else (artifacts['native-' + layer], raws[layer])
        e = rt.persist_layer(event, layer, n, raw, store,
                             route={'network_preflight': preflight} if layer in ('l2', 'l3') else None)
        event['layers'][layer] = {'s3_key': e['artifact_refs']['record']}
    return event, store.values


class ObservedStore(MemoryStore):
    def __init__(self, values, parallel=False):
        self.values = dict(values)
        self.gets, self.puts, self.threads = [], [], set()
        self.lock = Lock()
        self.barrier = Barrier(4) if parallel else None

    def get(self, key, optional=False):
        with self.lock:
            self.gets.append(key)
            self.threads.add(current_thread().name)
        if self.barrier is not None and key in self.layer_keys:
            self.barrier.wait(timeout=3)
        return super().get(key, optional)

    def put_bytes(self, key, data, exclusive=False):
        self.puts.append(key)
        return super().put_bytes(key, data, exclusive)


@pytest.mark.parametrize('case', list(CASES))
def test_combined_parallel_same_outputs_for_existing_page_cases(monkeypatch, case):
    event, values = prepared(monkeypatch, case)
    unchanged = deepcopy(event)
    monkeypatch.setenv('EVIDENCE_RESULT_CONTRACT', 'fast-result-1')
    monkeypatch.delenv('EVIDENCE_PARALLEL_READS', raising=False)
    before = ObservedStore(values)
    activity = rt.activity(event, before)
    context = rt.context({**event, 'url_activity': activity}, before)
    monkeypatch.setenv('EVIDENCE_PARALLEL_READS', '1')
    after = ObservedStore(values, parallel=True)
    after.layer_keys = {value['s3_key'] for value in event['layers'].values()}
    actual = rt.activity_context(event, after)
    assert actual == {'activity': activity, 'context': context}
    assert before.values == after.values
    assert event == unchanged
    assert before.puts == after.puts and len(after.puts) == 4
    assert len(before.gets) == 17 and len(after.gets) == 8
    assert len(after.threads) == 4


def test_corrupt_raw_stops_combined_before_any_write(monkeypatch):
    event, values = prepared(monkeypatch, 'login')
    values[rt.raw_key(event['job_id'], 1, 'l2')] = b'{}'
    store = ObservedStore(values)
    monkeypatch.setenv('EVIDENCE_PARALLEL_READS', '1')
    with pytest.raises(rt.PipelineServiceError, match='record_raw_hash_mismatch'):
        rt.activity_context(event, store)
    assert not store.puts


def test_activity_write_conflict_stops_context(monkeypatch):
    event, values = prepared(monkeypatch, 'login')
    key = f"records/{event['job_id']}/1/final/url-activity.json"
    values[key] = b'{}'
    store = ObservedStore(values)
    monkeypatch.setenv('EVIDENCE_PARALLEL_READS', '1')
    with pytest.raises(RuntimeError, match='immutable_artifact_conflict'):
        rt.activity_context(event, store)
    assert store.puts == [key]
