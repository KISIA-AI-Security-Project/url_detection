"""Safety and decision boundaries for the isolated parallel AWS candidate."""

import json
import io
import importlib.util
import sys
from hashlib import sha256
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from evidence_pipeline import aws_runtime
from evidence_pipeline.context import build_context
from test_url_activity import URL, inputs
from deployment.build_dns_parallel_candidate import patch_definition


@pytest.fixture(autouse=True)
def existing_dns_tests_do_not_collect_pages(monkeypatch):
    from evidence_pipeline import aws_l23_shared
    monkeypatch.setattr(aws_l23_shared, 'collect_outcomes',
                        lambda url, legacy: legacy.collect_outcomes(url, legacy.budget_seconds()))


class MemoryStore:
    def __init__(self, values=None):
        self.values = values or {}

    def get(self, key, optional=False):
        return self.values.get(key)

    def put(self, key, value, exclusive=False):
        self.values[key] = value
        return key

    def put_bytes(self, key, value, exclusive=False):
        self.values[key] = json.loads(value)
        return key


def test_l23_private_and_mixed_preflight_start_no_scanner(monkeypatch):
    calls = []
    monkeypatch.setattr(aws_runtime, 'load_existing_layer', lambda *args: None)
    def persist(_event, layer, _native, _raw, _store, *, route, failure):
        assert failure is not None
        return {'route': route, 'artifact_refs': {'record': f'{layer}.json', 'raw': f'{layer}-raw.json'},
                'analysis_status': 'FAILED'}
    monkeypatch.setattr(aws_runtime, 'persist_layer', persist)
    from url_collector import ssrf
    monkeypatch.setattr(ssrf, 'system_resolver', lambda *_args: ('8.8.8.8', '127.0.0.1'))
    legacy = SimpleNamespace(
        Outcome=lambda **kw: SimpleNamespace(result=None, timed_out=False, **kw),
        collect_outcomes=lambda *_args: calls.append('scanner'),
        derive_reach_state=lambda *_args: 'UNKNOWN',
        jsonable=lambda value: value)
    result = aws_runtime.l23({'job_id': 'job1', 'attempt': 1, 'url': URL}, legacy, MemoryStore())
    assert not calls
    preflight = result['network_preflight']
    assert preflight['state'] == 'blocked_before_layer_network'
    assert preflight['addresses'] == ['8.8.8.8', '127.0.0.1']
    assert preflight['layer_network_started'] is False


def no_network_legacy():
    def outcomes(url, _budget):
        value = {'target': {'original_url': url}, 'scan': {'status': 'failed'}, 'raw': {}}
        return {layer: SimpleNamespace(result=value, error=None, timed_out=False)
                for layer in ('l2', 'l3')}
    return SimpleNamespace(
        Outcome=lambda **kw: SimpleNamespace(result=None, timed_out=False, **kw),
        collect_outcomes=outcomes, budget_seconds=lambda: 1,
        derive_reach_state=lambda *_args: 'INACTIVE', jsonable=lambda value: value)


@pytest.mark.parametrize('url,address,family', [
    ('http://8.8.8.8/', '8.8.8.8', 'a_addresses'),
    ('http://[2606:4700:4700::1111]/', '2606:4700:4700::1111', 'aaaa_addresses')])
def test_public_literal_real_l23_record_to_activity(url, address, family):
    event = {'job_id': 'job1', 'attempt': 1, 'url': url}
    store = MemoryStore()
    result = aws_runtime.l23(event, no_network_legacy(), store)
    assert result['network_preflight']['addresses'] == [address]
    assert result['network_preflight'][family] == [address]
    aws_runtime.persist_layer(event, 'l0', {'target': {'original_url': url},
        'parse_status': 'SUCCESS', 'raw_evidence': {'raw_url': url}}, {'raw_url': url}, store)
    aws_runtime.persist_layer(event, 'l1', {'target': {'original_url': url},
        'job_id': 'job1', 'attempt_id': '1', '전체상태': '완료',
        '도메인단위': {'호스트 종류': 'IPv4' if family == 'a_addresses' else 'IPv6'},
        '인프라결과_목록': []}, {}, store)
    event['layers'] = {layer: {'s3_key': aws_runtime.record_key('job1', '1', layer)}
                       for layer in ('l0', 'l1', 'l2', 'l3')}
    activity = aws_runtime.activity(event, store)
    assert activity['url_activity_state'] == 'DNS_NOT_APPLICABLE'
    assert activity['skip_judgment'] is False
    for ref in store.values[activity['url_activity_key']]['source_references']:
        assert ref['sha256'] == aws_runtime.digest(store.values[ref['key']])


def test_private_literal_preflight_cause_survives_record_and_builder():
    url = 'http://127.0.0.1/'
    event = {'job_id': 'job1', 'attempt': 1, 'url': url}
    store = MemoryStore()
    calls = []
    legacy = no_network_legacy()
    legacy.collect_outcomes = lambda *_args: calls.append('scanner')
    result = aws_runtime.l23(event, legacy, store)
    assert not calls
    assert result['network_preflight']['addresses'] == ['127.0.0.1']
    assert result['network_preflight']['failure_kind'] == 'non_public_address'
    aws_runtime.persist_layer(event, 'l0', {'target': {'original_url': url},
        'parse_status': 'SUCCESS', 'raw_evidence': {'raw_url': url}}, {'raw_url': url}, store)
    aws_runtime.persist_layer(event, 'l1', {'target': {'original_url': url},
        '전체상태': '완료', '도메인단위': {'호스트 종류': 'IPv4'},
        '인프라결과_목록': []}, {}, store)
    records = [store.values[aws_runtime.record_key('job1', '1', layer)]['evidence_record']
               for layer in ('l0', 'l1', 'l2', 'l3')]
    raws = {layer: store.values[aws_runtime.raw_key('job1', '1', layer)]
            for layer in ('l0', 'l1', 'l2', 'l3')}
    for record in records[2:]:
        assert record['execution']['state'] == 'not_performed'
        assert record['acquisition']['state'] == 'not_attempted'
        assert record['causes'][0]['detail']['occurrence_id'] == 'job1:1:l23-preflight'
    document = build_context(records, raws)
    rendered = json.dumps(document)
    assert 'target resolves to a non-public address' in rendered
    assert 'l23_preflight_blocked' in rendered


def test_l1_nxdomain_and_l23_public_preflight_conflict_through_join(monkeypatch):
    from url_collector import ssrf
    monkeypatch.setattr(ssrf, 'system_resolver', lambda *_args: ('8.8.8.8',))
    event = {'job_id': 'job1', 'attempt': 1, 'url': URL}
    store = MemoryStore()
    native, raw = inputs()
    native.update(job_id='job1', attempt_id='1', target={'original_url': URL})
    aws_runtime.persist_layer(event, 'l0', {'target': {'original_url': URL},
        'parse_status': 'SUCCESS', 'raw_evidence': {'raw_url': URL}}, {'raw_url': URL}, store)
    aws_runtime.persist_layer(event, 'l1', native, raw, store)
    aws_runtime.l23(event, no_network_legacy(), store)
    event['layers'] = {layer: {'s3_key': aws_runtime.record_key('job1', '1', layer)}
                       for layer in ('l0', 'l1', 'l2', 'l3')}
    result = aws_runtime.activity(event, store)
    assert result['url_activity_state'] == 'DNS_CONFLICT'
    assert result['skip_judgment'] is False
    event['url_activity'] = result
    decision = store.values[result['url_activity_key']]
    original_hash = decision['source_references'][1]['sha256']
    decision['source_references'][1]['sha256'] = 'wrong-record-hash'
    event['url_activity']['url_activity_sha256'] = aws_runtime.digest(decision)
    with pytest.raises(aws_runtime.PipelineServiceError,
                       match='activity_source_reference_mismatch'):
        aws_runtime.context(event, store)
    decision['source_references'][1]['sha256'] = original_hash
    event['url_activity']['url_activity_sha256'] = aws_runtime.digest(decision)
    context = aws_runtime.context(event, store)
    assert context['skip_judgment'] is False
    document = store.values[context['final_key']]['model_context']
    assert document['url_activity_observation']['state'] == 'DNS_CONFLICT'
    assert document['url_activity_observation']['l23_preflight']['addresses'] == ['8.8.8.8']


def test_a_and_l23_dns_resolution_failures_mark_scan_time_unreachable(monkeypatch):
    from url_collector import ssrf
    def failed_resolution(*_args):
        raise OSError('resolver timed out')
    monkeypatch.setattr(ssrf, 'system_resolver', failed_resolution)
    event = {'job_id': 'job1', 'attempt': 1, 'url': URL}
    store = MemoryStore()
    native, raw = inputs('TIMEOUT')
    native.update(job_id='job1', attempt_id='1', target={'original_url': URL})
    aws_runtime.persist_layer(event, 'l0', {'target': {'original_url': URL},
        'parse_status': 'SUCCESS', 'raw_evidence': {'raw_url': URL}}, {'raw_url': URL}, store)
    aws_runtime.persist_layer(event, 'l1', native, raw, store)
    calls = []
    legacy = no_network_legacy()
    legacy.collect_outcomes = lambda *_args: calls.append('scanner')
    l23 = aws_runtime.l23(event, legacy, store)
    assert not calls
    assert l23['network_preflight']['failure_kind'] == 'dns_resolution_error'
    event['layers'] = {layer: {'s3_key': aws_runtime.record_key('job1', '1', layer)}
                       for layer in ('l0', 'l1', 'l2', 'l3')}
    result = aws_runtime.activity(event, store)
    assert result['url_activity_state'] == 'URL_UNREACHABLE_AT_SCAN'
    assert result['skip_judgment'] is True
    decision = store.values[result['url_activity_key']]
    assert decision['l1_address_observation'] == {
        'A': {'status': 'Timeout', 'result': None}}
    event['url_activity'] = result
    context = aws_runtime.context(event, store)
    assert context['analysis_status'] == 'NOT_REQUESTED'
    assert store.values[context['final_key']]['judgment_status'] == \
        'not_requested_url_unreachable_at_scan'
    assert 'model_context' not in store.values[context['final_key']]


def test_a_nodata_alone_marks_scan_time_unreachable(monkeypatch):
    from url_collector import ssrf
    monkeypatch.setattr(ssrf,'system_resolver',lambda *_args: (_ for _ in ()).throw(
        OSError('resolver returned no address')))
    event={'job_id':'job1','attempt':1,'url':URL}
    store=MemoryStore()
    native,raw=inputs('NODATA')
    native.update(job_id='job1',attempt_id='1',target={'original_url':URL})
    aws_runtime.persist_layer(event,'l0',{'target':{'original_url':URL},
        'parse_status':'SUCCESS','raw_evidence':{'raw_url':URL}}, {'raw_url':URL},store)
    aws_runtime.persist_layer(event,'l1',native,raw,store)
    aws_runtime.l23(event,no_network_legacy(),store)
    event['layers']={layer:{'s3_key':aws_runtime.record_key('job1','1',layer)}
                     for layer in ('l0','l1','l2','l3')}
    response=aws_runtime.activity(event,store)
    decision=store.values[response['url_activity_key']]
    assert decision['state']=='URL_UNREACHABLE_AT_SCAN'
    assert decision['reason']=='a_nodata_with_soa'
    assert decision['can_skip_judgment'] is True
    assert 'DNS AAAA' not in json.dumps(decision,ensure_ascii=False)
    event['url_activity'] = response
    context = aws_runtime.context(event, store)
    assert context['analysis_status'] == 'NOT_REQUESTED'
    assert store.values[context['final_key']]['judgment_status'] == \
        'not_requested_url_unreachable_at_scan'
    assert 'model_context' not in store.values[context['final_key']]


def test_l23_safety_block_is_not_dead_url(monkeypatch):
    from url_collector import ssrf
    monkeypatch.setattr(ssrf, 'system_resolver', lambda *_args: ('127.0.0.1',))
    event = {'job_id': 'job1', 'attempt': 1, 'url': URL}
    store = MemoryStore()
    native, raw = inputs('TIMEOUT')
    native.update(job_id='job1', attempt_id='1', target={'original_url': URL})
    aws_runtime.persist_layer(event, 'l0', {'target': {'original_url': URL},
        'parse_status': 'SUCCESS', 'raw_evidence': {'raw_url': URL}}, {'raw_url': URL}, store)
    aws_runtime.persist_layer(event, 'l1', native, raw, store)
    l23 = aws_runtime.l23(event, no_network_legacy(), store)
    assert l23['network_preflight']['failure_kind'] == 'non_public_address'
    event['layers'] = {layer: {'s3_key': aws_runtime.record_key('job1', '1', layer)}
                       for layer in ('l0', 'l1', 'l2', 'l3')}
    result = aws_runtime.activity(event, store)
    assert result['url_activity_state'] == 'DNS_UNKNOWN'
    assert result['skip_judgment'] is False


@pytest.mark.parametrize('addresses,expected', [(['8.8.8.8'], 'DNS_CONFLICT'),
                                               ([], 'DNS_NAME_NONEXISTENT_AT_SCAN')])
def test_joined_activity_accounts_for_preflight_address(monkeypatch, addresses, expected):
    native, raw = inputs()
    native.update(job_id='job1', attempt_id='1')
    records = [{'layer': layer, 'request_id': 'job1', 'attempt': '1',
                'target': {'original_url': URL}, 'provenance': {'mode': 'current'}}
               for layer in ('l0', 'l1', 'l2', 'l3')]
    refs = {layer: {'record': f'{layer}.json', 'raw': f'{layer}-raw.json',
                    'raw_sha256': 'raw', 'record_sha256': 'record'}
            for layer in ('l0', 'l1', 'l2', 'l3')}
    monkeypatch.setattr(aws_runtime, 'load_joined_layers',
                        lambda *_args, **_kwargs: (records, {'l1': raw}, refs,
                            {layer: values[aws_runtime.record_key('job1', '1', layer)]
                             for layer in ('l1', 'l2', 'l3')}))
    preflight = {'job_id': 'job1', 'attempt': 1, 'input_url': URL,
                 'hostname': 'example.test', 'addresses': addresses,
                 'a_addresses': addresses, 'aaaa_addresses': [],
                 'state': 'public_target_at_preflight' if addresses else 'blocked_before_layer_network',
                 'layer_network_started': bool(addresses),
                 'observed_at': datetime.now(timezone.utc).isoformat()}
    values = {aws_runtime.record_key('job1', '1', 'l1'): {'observation': native},
              **{aws_runtime.record_key('job1', '1', layer):
                 {'route': {'network_preflight': preflight}} for layer in ('l2', 'l3')}}
    store = MemoryStore(values)
    result = aws_runtime.activity({'job_id': 'job1', 'attempt': 1, 'url': URL,
                                   'layers': {layer: {'s3_key': f'{layer}.json'}
                                              for layer in ('l0', 'l1', 'l2', 'l3')}}, store)
    assert result['url_activity_state'] == expected
    assert result['skip_judgment'] is (not addresses)
    assert store.values[result['url_activity_key']]['l23_preflight']['addresses'] == addresses


def test_judgment_refuses_confirmed_name_absence_before_gateway_call():
    key = aws_runtime.record_key('job1', '1', 'final')
    decision_key = 'records/job1/1/final/url-activity.json'
    decision = {'request_id': 'job1', 'attempt': '1', 'input_url': URL,
                'state': 'DNS_NAME_NONEXISTENT_AT_SCAN', 'can_skip_judgment': True}
    envelope = {'integration_version': aws_runtime.VERSION, 'job_id': 'job1',
                'attempt': 1, 'input_url': URL, 'analysis_status': 'COMPLETED',
                'url_activity_key': decision_key,
                'url_activity_sha256': aws_runtime.digest(decision)}
    store = MemoryStore({key: envelope, decision_key: decision})
    with pytest.raises(aws_runtime.PipelineServiceError, match='judgment_forbidden'):
        aws_runtime.judgment({'job_id': 'job1', 'attempt': 1, 'url': URL,
                              'context_key': key}, store, object())


def test_context_skips_model_document_for_fresh_name_absence(monkeypatch):
    key = 'records/job1/1/final/url-activity.json'
    decision = {'request_id': 'job1', 'attempt': '1', 'input_url': URL,
                'state': 'DNS_NAME_NONEXISTENT_AT_SCAN', 'reason': 'a_nxdomain_with_soa',
                'can_skip_judgment': True,
                'valid_until': (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()}
    records = [{'layer': layer, 'execution': {}, 'acquisition': {}, 'analysis': {}}
               for layer in ('l0', 'l1', 'l2', 'l3')]
    refs = {layer: {'record': f'{layer}.json', 'raw': f'{layer}-raw.json',
                    'raw_sha256': 'raw', 'record_sha256': 'record'}
            for layer in ('l0', 'l1', 'l2', 'l3')}
    decision['source_references'] = [{'key': refs['l1']['raw'], 'sha256': 'raw'}] + [
        {'key': refs[layer]['record'], 'sha256': 'record'} for layer in ('l1', 'l2', 'l3')]
    monkeypatch.setattr(aws_runtime, 'load_joined_layers',
                        lambda *_args, **_kwargs: (records, {}, refs, {}))
    monkeypatch.setattr('evidence_pipeline.context.build_context',
                        lambda *_args, **_kwargs: pytest.fail('model document must not be built'))
    store = MemoryStore({key: decision})
    event = {'job_id': 'job1', 'attempt': 1, 'url': URL,
             'url_activity': {'url_activity_key': key,
                              'url_activity_sha256': aws_runtime.digest(decision),
                              'url_activity_state': decision['state'],
                              'skip_judgment': True}}
    result = aws_runtime.context(event, store)
    assert result['skip_judgment'] is True
    assert store.values[result['final_key']]['judgment_status'] == \
        'not_requested_dns_name_nonexistent_at_scan'
    assert 'model_context' not in store.values[result['final_key']]


def test_context_skips_for_fresh_a_nodata_without_aaaa(monkeypatch):
    key='records/job1/1/final/url-activity.json'
    decision={'request_id':'job1','attempt':'1','input_url':URL,
              'state':'URL_UNREACHABLE_AT_SCAN','reason':'a_nodata_with_soa',
              'can_skip_judgment':True,
              'valid_until':(datetime.now(timezone.utc)+timedelta(minutes=5)).isoformat(),
              'l23_preflight':{'addresses':[]}}
    records=[{'layer':layer,'execution':{},'acquisition':{},'analysis':{}}
             for layer in ('l0','l1','l2','l3')]
    refs={layer:{'record':f'{layer}.json','raw':f'{layer}-raw.json',
                 'raw_sha256':'raw','record_sha256':'record'}
          for layer in ('l0','l1','l2','l3')}
    decision['source_references']=[{'key':refs['l1']['raw'],'sha256':'raw'}]+[
        {'key':refs[layer]['record'],'sha256':'record'} for layer in ('l1','l2','l3')]
    monkeypatch.setattr(aws_runtime,'load_joined_layers',lambda *_args,**_kwargs:(records,{},refs,{}))
    monkeypatch.setattr('evidence_pipeline.context.build_context',lambda *_args,**_kwargs:
        pytest.fail('model document must not be built'))
    store=MemoryStore({key:decision})
    event={'job_id':'job1','attempt':1,'url':URL,
           'url_activity':{'url_activity_key':key,
                           'url_activity_sha256':aws_runtime.digest(decision),
                           'url_activity_state':decision['state'],'skip_judgment':True}}
    result=aws_runtime.context(event,store)
    assert result['skip_judgment'] is True
    decision['valid_until']=(datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()
    event['url_activity']['url_activity_sha256']=aws_runtime.digest(decision)
    with pytest.raises(aws_runtime.PipelineServiceError,match='activity_expired'):
        aws_runtime.context(event,store)


def test_asl_parallel_join_and_terminal_decision_contract():
    baseline = (Path(__file__).resolve().parents[3] / 'failure-causality-20260914' /
                'aws-integration-v1/deployment-r2-receipts/definition-deployed.json')
    functions = {role: 'arn:aws:lambda:ap-northeast-2:998301375101:function:isolated-' + role
                 for role in ('l0', 'l1', 'l23', 'activity', 'context', 'judgment')}
    states = patch_definition(json.loads(baseline.read_text(encoding='utf-8')), functions)['States']
    assert len(states['L0L1L23Parallel']['Branches']) == 3
    assert states['L0L1L23Parallel']['Next'] == 'ParallelJoinShape'
    assert states['JoinMalformed']['Next'] == 'MarkFailed'
    assert states['MarkObserved']['Next'] == 'ActivityTask'
    assert states['ActivityTask']['Parameters']['Payload']['operation'] == 'activity'
    assert states['MarkContext']['Next'] == 'URLActivityDecision'
    assert states['MarkDnsInactive']['Parameters']['ExpressionAttributeValues'][':st']['S'] == \
        'DNS_NAME_NONEXISTENT_AT_SCAN'
    assert any(choice['Next'] == 'MarkUrlUnreachable' for choice in
               states['URLActivityDecision']['Choices'])
    assert states['MarkUrlUnreachable']['Parameters']['ExpressionAttributeValues'][':st']['S'] == \
        'URL_UNREACHABLE_AT_SCAN'
    assert ':until' not in states['MarkUrlUnreachable']['Parameters']['ExpressionAttributeValues']
    assert 'REMOVE final_key, judgment_key, final_verdict' in \
        states['AllocAttempt']['Parameters']['UpdateExpression']


def test_context_lambda_dispatches_activity_without_new_function(monkeypatch):
    from evidence_pipeline import aws_clients
    monkeypatch.setattr(aws_clients, '_S3', None)
    fake_boto = SimpleNamespace(client=lambda service: object())
    monkeypatch.setitem(sys.modules, 'boto3', fake_boto)
    monkeypatch.setenv('EVIDENCE_ROLE', 'context')
    monkeypatch.setenv('OUTPUT_BUCKET', aws_runtime.BUCKET)
    monkeypatch.setattr(aws_runtime, 'activity', lambda event, store: ('activity', event['job_id']))
    monkeypatch.setattr(aws_runtime, 'context', lambda event, store, **kwargs: ('context', event['job_id']))
    assert aws_runtime.handler({'operation': 'activity', 'job_id': 'job1'}) == ('activity', 'job1')
    assert aws_runtime.handler({'operation': 'context', 'job_id': 'job1'}) == ('context', 'job1')
    with pytest.raises(ValueError, match='unknown_context_operation'):
        aws_runtime.handler({'operation': 'unknown', 'job_id': 'job1'})


@pytest.mark.parametrize('state', ['DNS_NAME_NONEXISTENT_AT_SCAN', 'URL_UNREACHABLE_AT_SCAN'])
def test_isolated_result_consumer_keeps_reachability_out_of_malicious_verdict(monkeypatch, state):
    job = 'a' * 32
    key = f'records/{job}/2/final/url-activity.json'
    decision = {'request_id': job, 'attempt': '2', 'input_url': URL,
                'state': state, 'can_skip_judgment': True}
    if state == 'DNS_NAME_NONEXISTENT_AT_SCAN':
        decision.update(reason='a_nxdomain_with_soa',
                        valid_until='2026-09-16T09:00:00+00:00')
    else:
        observed = '2026-09-16T09:00:00+00:00'
        decision.update(reason='l1_and_l23_address_resolution_failed', observed_at=observed,
                        scope='scan_time_reachability_observation',
                        l1_address_observation={
                            'A': {'status': 'Timeout', 'result': None}},
                        l23_preflight={'state': 'blocked_before_layer_network',
                                       'failure_kind': 'dns_resolution_error',
                                       'addresses': [], 'observed_at': observed,
                                       'error_type': 'ValueError',
                                       'reason': 'DNS resolution failed: Device or resource busy',
                                       'layer_network_started': False})
    digest = sha256(json.dumps(decision, ensure_ascii=False, sort_keys=True,
                               separators=(',', ':')).encode()).hexdigest()
    item = {'attempt': {'N': '2'}, 'status': {'S': state},
            'url': {'S': URL}, 'url_activity_key': {'S': key},
            'url_activity_sha256': {'S': digest}}
    if state == 'DNS_NAME_NONEXISTENT_AT_SCAN':
        item['url_activity_valid_until'] = {'S': decision['valid_until']}
    ddb = SimpleNamespace(get_item=lambda **_kw: {'Item': item})
    s3 = SimpleNamespace(get_object=lambda **_kw: {'Body': io.BytesIO(json.dumps(decision).encode())})
    fake_boto = SimpleNamespace(client=lambda service: {'dynamodb': ddb, 's3': s3}[service])
    monkeypatch.setitem(sys.modules, 'boto3', fake_boto)
    monkeypatch.setenv('JOBS_TABLE', 'isolated-table')
    monkeypatch.setenv('EVIDENCE_BUCKET', aws_runtime.BUCKET)
    path = Path(__file__).resolve().parents[1] / 'deployment/result/app.py'
    spec = importlib.util.spec_from_file_location('isolated_result_app', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    result = json.loads(module.handler({'pathParameters': {'scanId': job}}, None)['body'])
    assert result['status'] == 'COMPLETED'
    assert result['verdict'] == 'UNDETERMINED'
    assert result['url_activity']['state'] == state
    assert result['route'] == state
    assert result['url_activity']['valid_until'] == decision.get('valid_until')
    if state == 'URL_UNREACHABLE_AT_SCAN':
        assert result['url_activity']['scope'] == 'scan_time_reachability_observation'
        assert result['url_activity']['l1_address_observation']['A']['status'] == 'Timeout'
        assert result['url_activity']['l23_failure']['reason'].startswith('DNS resolution failed')
    item['url_activity_sha256']['S'] = 'wrong'
    result = json.loads(module.handler({'pathParameters': {'scanId': job}}, None)['body'])
    assert result['status'] == 'FAILED'


def test_isolated_result_consumer_accepts_fresh_a_nodata(monkeypatch):
    job='b'*32
    key=f'records/{job}/2/final/url-activity.json'
    decision={'request_id':job,'attempt':'2','input_url':URL,
              'state':'URL_UNREACHABLE_AT_SCAN','reason':'a_nodata_with_soa',
              'can_skip_judgment':True,
              'valid_until':(datetime.now(timezone.utc)+timedelta(minutes=5)).isoformat(),
              'l23_preflight':{'addresses':[]}}
    digest=sha256(json.dumps(decision,ensure_ascii=False,sort_keys=True,
                             separators=(',',':')).encode()).hexdigest()
    item={'attempt':{'N':'2'},'status':{'S':'URL_UNREACHABLE_AT_SCAN'},
          'url':{'S':URL},'url_activity_key':{'S':key},
          'url_activity_sha256':{'S':digest}}
    ddb=SimpleNamespace(get_item=lambda **_kw:{'Item':item})
    s3=SimpleNamespace(get_object=lambda **_kw:{'Body':io.BytesIO(json.dumps(decision).encode())})
    monkeypatch.setitem(sys.modules,'boto3',SimpleNamespace(client=lambda service:
        {'dynamodb':ddb,'s3':s3}[service]))
    monkeypatch.setenv('JOBS_TABLE','isolated-table')
    monkeypatch.setenv('EVIDENCE_BUCKET',aws_runtime.BUCKET)
    path=Path(__file__).resolve().parents[1]/'deployment/result/app.py'
    spec=importlib.util.spec_from_file_location('isolated_result_a_nodata',path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    result=json.loads(module.handler({'pathParameters':{'scanId':job}},None)['body'])
    assert result['status']=='COMPLETED'
    assert result['verdict']=='UNDETERMINED'
    assert result['url_activity']['valid_until']==decision['valid_until']
