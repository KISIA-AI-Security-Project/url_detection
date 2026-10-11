"""Adapters for the existing Step Functions events and project S3 prefixes.

Native scanners produce facts; records preserve; Context composes; Judgment interprets.
No AWS clients or network operations occur at module import.
"""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import io
import json
import os
import re
import urllib.error
from urllib.parse import urlsplit
import ipaddress

from .records import build_record, canonical, digest
from .record_contract import validate_record
from .performance import invocation, span, timed

VERSION = 'aws-dns-parallel-v1'
BUCKET = 'team5-evidence-998301375101-ap-northeast-2-an'
LAYERS = ('l0', 'l1', 'l2', 'l3')


class PipelineServiceError(RuntimeError):
    """Orchestration failure: must reach MarkFailed, never a URL UNKNOWN fallback."""


def identity(event, require_url=True):
    job, attempt = event.get('job_id'), event.get('attempt')
    if not isinstance(job, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}', job) or '..' in job:
        raise ValueError('invalid_job_id')
    prefix = os.environ.get('EVIDENCE_JOB_PREFIX')
    if prefix and (not re.fullmatch(r'[0-9a-f]{32}', job) or not job.startswith(prefix)):
        raise ValueError('job_outside_validation_scope')
    if type(attempt) not in (int, str) or not re.fullmatch(r'[1-9][0-9]*', str(attempt)) or int(attempt) > 2147483647:
        raise ValueError('invalid_attempt')
    url = event.get('url')
    if require_url and (not isinstance(url, str) or not url.strip()):
        raise ValueError('missing_input_url')
    return job, str(attempt), url


def record_key(job, attempt, layer):
    return f'records/{job}/{attempt}/{layer}/{layer}.json'


def raw_key(job, attempt, layer):
    return f'raw/{job}/{attempt}/{layer}/{layer}.json'


def error_code(exc):
    return str(getattr(exc, 'response', {}).get('Error', {}).get('Code', ''))


class Store:
    def __init__(self, s3, bucket=BUCKET, max_bytes=8_000_000):
        if bucket != BUCKET:
            raise ValueError('unexpected_evidence_bucket')
        self.s3, self.bucket, self.max_bytes = s3, bucket, max_bytes

    def get_bytes(self, key, optional=False):
        with span('s3.get', artifact='/'.join(key.split('/')[3:])) as timing:
            return self._get_bytes(key, optional, timing)

    def _get_bytes(self, key, optional, timing):
        try:
            response = self.s3.get_object(Bucket=self.bucket, Key=key)
        except Exception as exc:
            timing['retries'] = getattr(exc, 'response', {}).get('ResponseMetadata', {}).get('RetryAttempts')
            if optional and error_code(exc) in ('NoSuchKey', '404', 'NotFound'):
                return None
            raise
        timing['retries'] = response.get('ResponseMetadata', {}).get('RetryAttempts')
        body = response['Body']
        try:
            data = body.read(self.max_bytes + 1)
        finally:
            body.close()
        if len(data) > self.max_bytes:
            raise PipelineServiceError('stored_object_size_limit')
        timing['bytes'] = len(data)
        return data

    def get(self, key, optional=False):
        data = self.get_bytes(key, optional)
        with span('storage.decode'):
            return None if data is None else json.loads(data)

    def put_bytes(self, key, data, exclusive=False):
        try:
            with span('s3.put', artifact='/'.join(key.split('/')[3:]), bytes=len(data)) as timing:
                try:
                    response = self.s3.put_object(Bucket=self.bucket, Key=key, Body=data,
                                                 ContentType='application/json; charset=utf-8', IfNoneMatch='*')
                except Exception as exc:
                    timing['retries'] = getattr(exc, 'response', {}).get('ResponseMetadata', {}).get('RetryAttempts')
                    raise
                timing['retries'] = (response or {}).get('ResponseMetadata', {}).get('RetryAttempts')
        except Exception as exc:
            if error_code(exc) not in ('PreconditionFailed', '412', 'ConditionalRequestConflict', '409'):
                raise
            if exclusive or self.get_bytes(key) != data:
                raise PipelineServiceError('immutable_artifact_conflict') from None
        return key

    def put(self, key, value, exclusive=False):
        with span('storage.encode'):
            data = canonical(value)
        return self.put_bytes(key, data, exclusive)


def layer_result(envelope):
    return {'s3_key': envelope['artifact_refs']['record'],
            'raw_key': envelope['artifact_refs']['raw'],
            'analysis_status': envelope['analysis_status']}


def load_existing_layer(event, layer, store):
    job, attempt, url = identity(event)
    value = store.get(record_key(job, attempt, layer), optional=True)
    if value is not None:
        check_layer(value, job, attempt, url, layer)
        raw = store.get(raw_key(job, attempt, layer))
        if digest(raw) != value['evidence_record']['raw_ref']['sha256']:
            raise PipelineServiceError('record_raw_hash_mismatch')
    return value


def check_layer(value, job, attempt, url, layer):
    if (value.get('integration_version'), value.get('job_id'), str(value.get('attempt')),
        value.get('input_url'), value.get('layer')) != (VERSION, job, attempt, url, layer):
        raise PipelineServiceError('layer_identity_or_version_mismatch')
    rec = validate_record(value['evidence_record'])
    if (rec['request_id'], rec['attempt'], rec['layer']) != (job, attempt, layer):
        raise PipelineServiceError('normalized_record_identity_mismatch')
    if value['artifact_refs'] != {'record': record_key(job, attempt, layer),
                                  'raw': raw_key(job, attempt, layer)}:
        raise PipelineServiceError('layer_artifact_reference_mismatch')


@timed('record.persist')
def persist_layer(event, layer, native, raw, store, *, route=None, failure=None):
    job, attempt, url = identity(event)
    execution_kind = os.environ.get('EVIDENCE_EXECUTION_KIND', 'lambda')
    if execution_kind not in ('lambda', 'ec2'):
        raise ValueError('unsupported_evidence_execution_kind')
    result = deepcopy(native)
    result.setdefault('target', {'original_url': url})
    if failure:
        result.setdefault('errors', []).append(failure)
    with span('record.build'):
        rec = build_record(layer, result, request_id=job, attempt=attempt, raw=raw)
    if failure and failure.get('timed_out'):
        rec['execution'].update(state='interrupted', reason='lambda_layer_budget_exceeded')
        validate_record(rec)
    # Existing SFN progress vocabulary is a compatibility projection, not a verdict.
    status = ('NOT_PERFORMED' if rec['execution']['state'] == 'not_performed' else
              'FAILED' if failure else 'COMPLETED' if rec['analysis_status'] == 'COMPLETED' else 'PARTIAL')
    refs = {'raw': raw_key(job, attempt, layer), 'record': record_key(job, attempt, layer)}
    envelope = {'schema_version': '2.0', 'integration_version': VERSION,
                'job_id': job, 'attempt': int(attempt), 'layer': layer, 'input_url': url,
                'analysis_status': status, 'observation': deepcopy(native),
                'evidence_record': rec, 'raw_refs': [refs['raw']], 'artifact_refs': refs,
                'route': route or {}, 'notes': [], 'limitations': [],
                'produced_by': {'kind': execution_kind, 'integration': VERSION}}
    store.put(refs['raw'], raw)
    store.put(refs['record'], envelope)
    return envelope


def l0(event, legacy, store):
    job, attempt, url = identity(event)
    envelope = load_existing_layer(event, 'l0', store)
    if envelope is None:
        with span('analysis.l0'):
            native = legacy.jsonable(legacy.analyze(url))
        envelope = persist_layer(event, 'l0', native, native.get('raw_evidence', {}), store)
    return {'job_id': job, 'attempt': int(attempt), 'layer': 'l0', **layer_result(envelope)}


def l1(event, legacy, store):
    from urllib.parse import urlsplit
    job, attempt, url = identity(event)
    envelope = load_existing_layer(event, 'l1', store)
    if envelope is None:
        try:
            with span('collection.l1'):
                native, raw = legacy.run(url, job, attempt)
        except Exception as exc:
            route = {'gate_block': True, 'block_reason': legacy.BLOCKED_L1_FAILED, 'resolved_ips': []}
            envelope = persist_layer(event, 'l1', {}, {}, store, route=route,
                failure={'code': 'layer_execution_failed', 'stage': 'l1_run', 'error_type': type(exc).__name__})
        else:
            native, raw = legacy.jsonable(native), legacy.jsonable(raw)
            gate = legacy.derive_gate(native, urlsplit(url).hostname)
            route = {'gate_block': gate.gate_block, 'block_reason': gate.block_reason,
                     'resolved_ips': list(gate.resolved_ips), 'host_kind': gate.host_kind}
            envelope = persist_layer(event, 'l1', native, raw, store, route=route)
    return {'job_id': job, 'attempt': int(attempt), 'layer': 'l1', **layer_result(envelope),
            'raw_keys': envelope['raw_refs'], **envelope['route']}


def l23(event, legacy, store):
    job, attempt, url = identity(event)
    existing = {layer: load_existing_layer(event, layer, store) for layer in ('l2', 'l3')}
    if all(existing.values()):
        written = existing
    elif any(existing.values()):
        # One preserved result must not cause the other layer to trigger recollection.
        raise PipelineServiceError('partial_l23_commit_requires_existing_attempt_recovery')
    else:
        # The old SFN L1 gate no longer precedes this parallel branch. Fail
        # closed before *any* L2/L3 network work; each collector still guards
        # and pins every target connection and redirect independently.
        with span('bootstrap.collector_import'):
            from url_collector.ssrf import resolve_public_http_url, system_resolver
        try:
            hostname = urlsplit(url).hostname
        except ValueError:
            hostname = None
        observed = {'schema_version': 'l23-preflight-1', 'job_id': job,
                    'attempt': int(attempt), 'input_url': url,
                    'hostname': hostname,
                    'started_at': datetime.now(timezone.utc).isoformat(),
                    'resolver': 'getaddrinfo_combined', 'addresses': [],
                    'a_addresses': [], 'aaaa_addresses': [],
                    'a_status': 'not_separately_queried',
                    'aaaa_status': 'not_separately_queried'}
        try:
            literal = str(ipaddress.ip_address(hostname))
        except (ValueError, TypeError):
            literal = None
        if literal is not None:
            observed['resolver'] = 'ip_literal'
            observed['addresses'] = [literal]
            family = 'a_addresses' if ipaddress.ip_address(literal).version == 4 else 'aaaa_addresses'
            observed[family] = [literal]
            observed['a_status'] = 'literal' if family == 'a_addresses' else 'not_applicable'
            observed['aaaa_status'] = 'literal' if family == 'aaaa_addresses' else 'not_applicable'
        def capturing_resolver(hostname, port):
            addresses = tuple(system_resolver(hostname, port))
            observed['addresses'] = list(addresses)
            for address in addresses:
                family = 'a_addresses' if ipaddress.ip_address(address).version == 4 else 'aaaa_addresses'
                observed[family].append(address)
            observed['a_status'] = 'addresses_observed' if observed['a_addresses'] else 'none_in_combined_lookup'
            observed['aaaa_status'] = 'addresses_observed' if observed['aaaa_addresses'] else 'none_in_combined_lookup'
            return addresses
        try:
            with span('collection.preflight'):
                target = resolve_public_http_url(url, capturing_resolver)
        except (ValueError, OSError) as exc:
            outcomes = {layer: legacy.Outcome(error=exc) for layer in ('l2', 'l3')}
            reason = str(exc)[:200]
            if observed['addresses'] and any(
                    not ipaddress.ip_address(address).is_global or
                    ipaddress.ip_address(address).is_multicast
                    for address in observed['addresses']):
                failure_kind = 'non_public_address'
            elif reason.startswith('DNS resolution') or reason == 'DNS resolution returned no addresses':
                failure_kind = 'dns_resolution_error'
            elif not observed['addresses']:
                failure_kind = 'url_validation_or_dns_error'
            else:
                failure_kind = 'preflight_validation_error'
            preflight = {**observed, 'state': 'blocked_before_layer_network',
                         'observed_at': datetime.now(timezone.utc).isoformat(),
                         'failure_kind': failure_kind,
                         'error_type': type(exc).__name__, 'reason': reason,
                         'layer_network_started': False}
        else:
            preflight = {**observed, 'state': 'public_target_at_preflight',
                         'observed_at': datetime.now(timezone.utc).isoformat(),
                         'addresses': list(target.addresses), 'layer_network_started': True}
            from .aws_l23_shared import collect_outcomes
            try:
                outcomes = collect_outcomes(url, legacy)
            except Exception as exc:
                outcomes = {layer: legacy.Outcome(error=exc) for layer in ('l2', 'l3')}
        reach = legacy.derive_reach_state(outcomes['l2'].result, outcomes['l3'].result)
        if any(((outcome.result or {}).get('shared_page_observation') or {}).get('response_received')
               for outcome in outcomes.values()):
            reach = 'ACTIVE'
        written = {}
        for layer in ('l2', 'l3'):
            outcome = outcomes[layer]
            native = legacy.jsonable(outcome.result) if outcome.result is not None else {}
            failure = None
            if preflight['state'] == 'blocked_before_layer_network':
                native = {'target': {'original_url': url}, 'scan': {'status': 'not_started'},
                          'producer_execution': {'state': 'not_performed',
                                                 'reason': 'l23_preflight_blocked'},
                          'preflight': preflight}
                failure = {'code': 'l23_preflight_blocked',
                           'occurrence_id': f'{job}:{attempt}:l23-preflight',
                           'stage': 'before_l2_l3_network', 'impact_scope': 'acquisition',
                           'url': url, 'hostname': preflight['hostname'],
                           'affected_layers': ['l2', 'l3'],
                           'failure_kind': preflight['failure_kind'],
                           'reason': preflight['reason'],
                           'observed_at': preflight['observed_at'],
                           'addresses': preflight['addresses'],
                           'reason_scope': 'One shared L23 preflight blocked both scanner starts.'}
            elif outcome.error is not None or outcome.timed_out:
                failure = {'code': 'layer_execution_failed', 'stage': 'lambda_layer_run',
                           'error_type': type(outcome.error).__name__ if outcome.error else 'TimeoutError',
                           'timed_out': bool(outcome.timed_out)}
            written[layer] = persist_layer(event, layer, native, native.get('raw', {}), store,
                                           route={'reach_state': reach, 'network_preflight': preflight}, failure=failure)
    return {'job_id': job, 'attempt': int(attempt), 'layer': 'l23',
            'reach_state': written['l2']['route']['reach_state'],
            'network_preflight': written['l2']['route'].get('network_preflight'),
            **{layer: layer_result(value) for layer, value in written.items()}}


@timed('context.load_and_validate_layers')
def load_joined_layers(event, store, *, include_envelopes=False):
    job, attempt, url = identity(event)
    records, raws, refs, envelopes = [], {}, {}, {}
    expected = event['layers']
    if set(expected) != set(LAYERS):
        raise PipelineServiceError('context_layer_set_mismatch')
    for layer in LAYERS:
        # No prefix enumeration and no silent fallback to historical envelopes.
        if expected[layer]['s3_key'] != record_key(job, attempt, layer):
            raise PipelineServiceError('missing_or_mismatched_layer_record')

    def load_one(layer):
        value = store.get(expected[layer]['s3_key'])
        check_layer(value, job, attempt, url, layer)
        raw = store.get(raw_key(job, attempt, layer))
        if digest(raw) != value['evidence_record']['raw_ref']['sha256']:
            raise PipelineServiceError('record_raw_hash_mismatch')
        return value, raw

    if os.environ.get('EVIDENCE_PARALLEL_READS') == '1':
        from concurrent.futures import ThreadPoolExecutor
        from contextvars import copy_context
        # Each worker has the invocation's diagnostic context. All reads finish
        # before returning or raising; no request work escapes this invocation.
        with ThreadPoolExecutor(max_workers=len(LAYERS)) as pool:
            futures = [pool.submit(copy_context().run, load_one, layer) for layer in LAYERS]
            loaded = [future.result() for future in futures]
    else:
        loaded = [load_one(layer) for layer in LAYERS]
    for layer, (value, raw) in zip(LAYERS, loaded):
        records.append(value['evidence_record']); raws[layer] = raw
        envelopes[layer] = value
        refs[layer] = {**value['artifact_refs'], 'record_sha256': digest(value), 'raw_sha256': digest(raw)}
    return (records, raws, refs, envelopes) if include_envelopes else (records, raws, refs)


@timed('activity.total')
def activity(event, store):
    joined = load_joined_layers(event, store, include_envelopes=True)
    reference, _ = _activity_from_layers(event, store, joined)
    return reference


def _activity_from_layers(event, store, joined):
    with span('bootstrap.activity_import'):
        from .url_activity import assess_url_activity, l1_address_resolution_failed
    job, attempt, url = identity(event)
    records, raws, refs, envelopes = joined
    l1, l2, l3 = (envelopes[layer] for layer in ('l1', 'l2', 'l3'))
    preflight = l2['route'].get('network_preflight')
    if not isinstance(preflight, dict) or preflight != l3['route'].get('network_preflight'):
        raise PipelineServiceError('l23_preflight_missing_or_mismatched')
    if (preflight.get('job_id'), str(preflight.get('attempt')), preflight.get('input_url')) != (job, attempt, url):
        raise PipelineServiceError('l23_preflight_identity_mismatch')
    try:
        peer_host = urlsplit(url).hostname
    except ValueError:
        peer_host = None
    if preflight.get('hostname') != peer_host or not isinstance(preflight.get('addresses'), list):
        raise PipelineServiceError('l23_preflight_target_mismatch')
    if (preflight.get('state') not in ('blocked_before_layer_network', 'public_target_at_preflight') or
            not isinstance(preflight.get('a_addresses'), list) or
            not isinstance(preflight.get('aaaa_addresses'), list) or
            set(preflight['addresses']) != set(preflight['a_addresses'] + preflight['aaaa_addresses'])):
        raise PipelineServiceError('l23_preflight_shape_mismatch')
    if (preflight['state'] == 'public_target_at_preflight' and
            (not preflight['addresses'] or preflight.get('layer_network_started') is not True)):
        raise PipelineServiceError('l23_preflight_public_inconsistent')
    if (preflight['state'] == 'blocked_before_layer_network' and
            preflight.get('layer_network_started') is not False):
        raise PipelineServiceError('l23_preflight_block_inconsistent')
    try:
        preflight_at = datetime.fromisoformat(preflight['observed_at'].replace('Z', '+00:00'))
    except (KeyError, AttributeError, ValueError) as exc:
        raise PipelineServiceError('l23_preflight_time_missing') from exc
    if preflight_at.tzinfo is None or preflight_at > datetime.now(timezone.utc):
        raise PipelineServiceError('l23_preflight_time_invalid')
    for address in preflight['addresses']:
        try:
            ipaddress.ip_address(address)
        except ValueError as exc:
            raise PipelineServiceError('l23_preflight_address_malformed') from exc
    with span('activity.assess'):
        decision = assess_url_activity(url, l1['observation'], raws['l1'], records,
                                       request_id=job, attempt=attempt)
    if decision['state'] in ('DNS_NAME_NONEXISTENT_AT_SCAN','URL_UNREACHABLE_AT_SCAN') and preflight['addresses']:
        decision = {**decision, 'state': 'DNS_CONFLICT',
                    'reason': 'l1_a_negative_and_l23_preflight_address',
                    'can_skip_judgment': False}
    if (decision['state'] == 'DNS_UNKNOWN' and
            decision['identity_binding'] == 'verified' and
            not decision['l23_positive_observation'] and
            l1_address_resolution_failed(url, l1['observation'], raws['l1']) and
            preflight['state'] == 'blocked_before_layer_network' and
            preflight.get('failure_kind') == 'dns_resolution_error' and
            not preflight['addresses']):
        address_items = {item.get('name'): item for item in
                         l1['observation']['인프라결과_목록'] if isinstance(item, dict)}
        l1_address_observation = {
            kind: {'status': address_items[f'DNS {kind}'].get('status'),
                   'result': address_items[f'DNS {kind}'].get('result')}
            for kind in ('A',)}
        decision = {**decision, 'state': 'URL_UNREACHABLE_AT_SCAN',
                    'reason': 'l1_and_l23_address_resolution_failed',
                    'scope': 'scan_time_reachability_observation',
                    'l1_address_observation': l1_address_observation,
                    'observed_at': preflight['observed_at'], 'can_skip_judgment': True}
    decision = {**decision, 'request_id': job, 'attempt': attempt,
                'input_url': url, 'l23_preflight': preflight,
                'source_references': [
                    {'key': refs['l1']['raw'], 'sha256': refs['l1']['raw_sha256']},
                    *({'key': refs[layer]['record'],
                       'sha256': refs[layer]['record_sha256']}
                      for layer in ('l1', 'l2', 'l3'))]}
    activity_key = f'records/{job}/{attempt}/final/url-activity.json'
    store.put(activity_key, decision)
    reference = {'job_id': job, 'attempt': int(attempt), 'url_activity_key': activity_key,
            'url_activity_sha256': digest(decision), 'url_activity_state': decision['state'],
            'skip_judgment': decision['can_skip_judgment'],
            'valid_until': decision.get('valid_until')}
    return reference, decision


@timed('context.total')
def context(event, store, *, max_bytes=400_000):
    joined = load_joined_layers(event, store, include_envelopes=True)
    return _context_from_layers(event, store, joined, max_bytes=max_bytes)


def _context_from_layers(event, store, joined, *, max_bytes=400_000, stored_decision=None):
    job, attempt, url = identity(event)
    records, raws, refs, envelopes = joined
    decision_ref = event.get('url_activity')
    activity_key = f'records/{job}/{attempt}/final/url-activity.json'
    if not isinstance(decision_ref, dict) or decision_ref.get('url_activity_key') != activity_key:
        raise PipelineServiceError('explicit_activity_key_required')
    decision = store.get(activity_key) if stored_decision is None else stored_decision
    if (digest(decision) != decision_ref.get('url_activity_sha256') or
            decision.get('request_id') != job or str(decision.get('attempt')) != attempt or
            decision.get('input_url') != url or
            decision.get('state') != decision_ref.get('url_activity_state') or
            decision.get('can_skip_judgment') is not decision_ref.get('skip_judgment')):
        raise PipelineServiceError('activity_binding_mismatch')
    expected_sources = [{'key': refs['l1']['raw'], 'sha256': refs['l1']['raw_sha256']}] + [
        {'key': refs[layer]['record'], 'sha256': refs[layer]['record_sha256']}
        for layer in ('l1', 'l2', 'l3')]
    if decision.get('source_references') != expected_sources:
        raise PipelineServiceError('activity_source_reference_mismatch')
    if decision.get('can_skip_judgment'):
        if decision['state'] == 'DNS_NAME_NONEXISTENT_AT_SCAN':
            try:
                deadline = datetime.fromisoformat(decision['valid_until'].replace('Z', '+00:00'))
            except (KeyError, AttributeError, ValueError) as exc:
                raise PipelineServiceError('activity_expiry_missing') from exc
            if deadline.tzinfo is None or deadline <= datetime.now(timezone.utc):
                raise PipelineServiceError('activity_expired')
            judgment_status = 'not_requested_dns_name_nonexistent_at_scan'
        elif decision['state'] == 'URL_UNREACHABLE_AT_SCAN':
            if decision.get('reason')=='a_nodata_with_soa':
                try:
                    deadline=datetime.fromisoformat(decision['valid_until'].replace('Z','+00:00'))
                except (KeyError,AttributeError,ValueError) as exc:
                    raise PipelineServiceError('activity_expiry_missing') from exc
                if deadline.tzinfo is None or deadline<=datetime.now(timezone.utc):
                    raise PipelineServiceError('activity_expired')
                if (decision.get('l23_preflight') or {}).get('addresses'):
                    raise PipelineServiceError('unreachable_activity_mismatch')
            else:
                preflight = decision.get('l23_preflight') or {}
                if (decision.get('reason') != 'l1_and_l23_address_resolution_failed' or
                        decision.get('scope') != 'scan_time_reachability_observation' or
                        set((decision.get('l1_address_observation') or {})) != {'A'} or
                        preflight.get('state') != 'blocked_before_layer_network' or
                        preflight.get('failure_kind') != 'dns_resolution_error' or
                        preflight.get('addresses') != [] or
                        preflight.get('observed_at') != decision.get('observed_at')):
                    raise PipelineServiceError('unreachable_activity_mismatch')
            judgment_status = 'not_requested_url_unreachable_at_scan'
        else:
            raise PipelineServiceError('unsupported_skip_judgment_state')
        if os.environ.get('EVIDENCE_RESULT_CONTRACT') == 'fast-result-1':
            with span('bootstrap.context_import'):
                from .aws_fast_result import persist_context
            return persist_context(event, store, records, raws, refs, decision, max_bytes=max_bytes,
                                   native=envelopes['l3']['observation'])
        key = record_key(job, attempt, 'final')
        output = {'integration_version': VERSION, 'job_id': job, 'attempt': int(attempt),
                  'input_url': url, 'analysis_status': 'NOT_REQUESTED',
                  'judgment_status': judgment_status,
                  'url_activity_key': activity_key, 'url_activity_sha256': digest(decision),
                  'coverage': {r['layer']: {k: r[k] for k in
                               ('execution', 'acquisition', 'analysis')} for r in records}}
        store.put(key, output)
        return {'job_id': job, 'attempt': int(attempt), 'final_key': key,
                'analysis_status': 'NOT_REQUESTED',
                'url_activity_key': activity_key, 'url_activity_sha256': digest(decision),
                'url_activity_state': decision['state'], 'skip_judgment': True}
    if os.environ.get('EVIDENCE_RESULT_CONTRACT') == 'fast-result-1':
        with span('bootstrap.context_import'):
            from .aws_fast_result import persist_context
        return persist_context(event, store, records, raws, refs, decision, max_bytes=max_bytes,
                               native=envelopes['l3']['observation'])
    from .context import build_context
    from .pipeline import render_context
    audit = {}
    document = build_context(records, raws, max_bytes=max_bytes, audit=audit)
    document['url_activity_observation'] = {
        'state': decision['state'], 'reason': decision['reason'],
        'scope': 'scan_time_technical_observation_not_maliciousness_verdict',
        'l23_preflight': {'state': decision['l23_preflight']['state'],
                          'addresses': decision['l23_preflight']['addresses']}}
    audit['model_context_sha256'] = digest(document)
    if len(render_context(document).encode('utf-8')) > max_bytes:
        raise PipelineServiceError('context_budget_exceeded_after_activity')
    key = record_key(job, attempt, 'final')
    audit.update(s3_artifacts=refs, input_url=url)
    audit_key = f'records/{job}/{attempt}/final/context-audit.json'
    store.put(audit_key, audit)
    # Store ordered model JSON separately from provenance. Only model_context is sent.
    output = {'integration_version': VERSION, 'job_id': job, 'attempt': int(attempt), 'input_url': url,
              'analysis_status': 'COMPLETED', 'model_context': document,
              'url_activity_key': activity_key, 'url_activity_sha256': digest(decision),
              'model_context_sha256': hashlib.sha256(render_context(document).encode()).hexdigest(),
              'audit_key': audit_key, 'coverage': {r['layer']: {k: r[k] for k in ('execution','acquisition','analysis')} for r in records}}
    store.put_bytes(key, json.dumps(output, ensure_ascii=False, separators=(',', ':')).encode())
    return {'job_id': job, 'attempt': int(attempt), 'final_key': key,
            'context_sha256': output['model_context_sha256'], 'analysis_status': 'COMPLETED',
            'url_activity_key': activity_key, 'url_activity_sha256': digest(decision),
            'url_activity_state': decision['state'],
            'skip_judgment': decision['can_skip_judgment']}


@timed('activity_context.total')
def activity_context(event, store, *, max_bytes=400_000):
    """One request, one validated snapshot, unchanged four durable artifacts."""
    from .stage_deadline import hard_stage_deadline
    with hard_stage_deadline('activity'):
        joined = load_joined_layers(event, store, include_envelopes=True)
        with span('activity.total'):
            reference, decision = _activity_from_layers(event, store, joined)
    # _activity_from_layers returns only after the immutable PUT has completed.
    # Context retains all decision binding, source-reference and expiry checks.
    with hard_stage_deadline('context'):
        with span('context.total'):
            result = _context_from_layers({**event, 'url_activity': reference}, store, joined,
                                          max_bytes=max_bytes, stored_decision=decision)
    return {'activity': reference, 'context': result}


def judgment(event, store, gateway):
    if os.environ.get('EVIDENCE_RESULT_CONTRACT') == 'fast-result-1':
        from .aws_fast_result import run_judgment
        return run_judgment(event, store, lambda: gateway)
    from .pipeline import SYSTEM_PROMPT, render_context, validate_judgment
    job, attempt, url = identity(event)
    key = record_key(job, attempt, 'final')
    if event.get('context_key') != key:
        raise PipelineServiceError('explicit_builder_key_required')
    envelope = store.get(key)
    if (envelope.get('integration_version'), envelope.get('job_id'), str(envelope.get('attempt')),
        envelope.get('input_url'), envelope.get('analysis_status')) != (VERSION, job, attempt, url, 'COMPLETED'):
        raise PipelineServiceError('context_identity_mismatch')
    decision = store.get(envelope.get('url_activity_key', ''))
    if (digest(decision) != envelope.get('url_activity_sha256') or
            decision.get('request_id') != job or str(decision.get('attempt')) != attempt or
            decision.get('input_url') != url):
        raise PipelineServiceError('activity_binding_mismatch')
    if decision.get('can_skip_judgment') or decision.get('state') in (
            'DNS_NAME_NONEXISTENT_AT_SCAN', 'URL_UNREACHABLE_AT_SCAN'):
        raise PipelineServiceError('judgment_forbidden_by_dns_activity')
    document = envelope['model_context']
    user = render_context(document)
    if hashlib.sha256(user.encode()).hexdigest() != envelope['model_context_sha256'] or event.get('context_sha256') != envelope['model_context_sha256']:
        raise PipelineServiceError('context_hash_mismatch')
    final_key = f'judgments/{job}/{attempt}.json'
    artifacts = f'judgments/{job}/{attempt}/'
    body = json.dumps(gateway._payload(SYSTEM_PROMPT, user), ensure_ascii=False, separators=(',', ':')).encode()
    request_hash = hashlib.sha256(body).hexdigest()
    existing = store.get(final_key, optional=True)
    if existing is not None:
        if (existing.get('job_id'), str(existing.get('attempt')), existing.get('request_sha256'),
            existing.get('judgment_status')) != (job, attempt, request_hash, 'completed'):
            raise PipelineServiceError('existing_judgment_binding_mismatch')
        validate_judgment(existing, document, require_observations=True)
        return {'job_id': job, 'attempt': int(attempt), 'verdict': existing['verdict'],
                'judgment_status': 'completed', 'judgment_key': final_key}
    store.put(artifacts+'request-claim.json', {'request_sha256': request_hash,
              'context_sha256': envelope['model_context_sha256'], 'model': gateway.model}, exclusive=True)
    store.put_bytes(artifacts+'request.json', body)
    transport = {'api': 'openai_chat_completions' if gateway.endpoint == '/v1/chat/completions' else 'anthropic_messages',
                 'endpoint': gateway.url, 'requested_model': gateway.model,
                 'http_status': None, 'request_sha256': request_hash}
    received = {'seen': False, 'headers_seen': False, 'body': b'', 'read_limit_reached': False,
                'read_state': 'not_started', 'read_error_type': None}
    def capture_bytes(data, limit):
        bound = min(131073, limit) if limit is not None and limit >= 0 else 131073
        received.update(seen=True, body=data[:bound],
                        read_limit_reached=(limit is not None and limit >= 0 and len(data) >= limit))
    def read_response(response, size):
        try:
            data = response.read(size)
        except Exception as exc:
            finish = getattr(gateway, '_finish_transport', None)
            if callable(finish):
                finish('body_read_failed', False)
            partial = getattr(exc, 'partial', None)
            if isinstance(partial, (bytes, bytearray)):
                capture_bytes(bytes(partial), size)
                received['read_state'] = 'failed_partial'
            else:
                received['read_state'] = 'failed_no_capture'
            received['read_error_type'] = type(exc).__name__
            raise
        finish = getattr(gateway, '_finish_transport', None)
        if callable(finish):
            finish('http_error_body_received' if (transport['http_status'] or 0) >= 400 else 'body_received', True)
        capture_bytes(data, size)
        received['read_state'] = 'completed'
        return data
    class CapturedResponse:
        def __init__(self, response):
            self.response = response
        def __enter__(self):
            self.response.__enter__()
            return self
        def __exit__(self, *args):
            return self.response.__exit__(*args)
        def read(self, size=-1):
            return read_response(self.response, size)
    original_open = gateway.open
    def capture_transport(request, **kwargs):
        try:
            response = original_open(request, **kwargs)
        except urllib.error.HTTPError as exc:
            transport['http_status'] = exc.code
            received['headers_seen'] = True
            # Preserve the same bounded bytes the original Gateway reads, then replay
            # those bytes to its existing error parser. Never retry the HTTP request.
            try:
                data = read_response(exc, 8192)
            finally:
                exc.close()
            raise urllib.error.HTTPError(exc.url, exc.code, exc.msg, exc.headers, io.BytesIO(data)) from None
        except Exception as exc:
            transport['http_status'] = getattr(exc, 'code', None)
            raise
        transport['http_status'] = getattr(response, 'status', None)
        received['headers_seen'] = True
        return CapturedResponse(response)
    gateway.open = capture_transport
    stage = 'gateway'
    try:
        value = gateway(SYSTEM_PROMPT, user)
        if gateway.last_request_body != body:
            raise PipelineServiceError('gateway_wire_mismatch')
        stage = 'validation'
        if not isinstance(value, dict) or set(value) != {'verdict', 'summary', 'observations', 'reasons',
                                                         'limitations', 'deep_analysis_needed'}:
            raise ValueError('unexpected_judgment_fields')
        validate_judgment(value, document, require_observations=True)
    except Exception as exc:
        detail = getattr(exc, 'detail', {})
        store.put(artifacts+'failure.json', {'judgment_status': 'output_validation_failed' if stage=='validation' else 'service_failed',
                  'stage': stage, 'error_type': type(exc).__name__, 'request_sha256': request_hash,
                  'kind': detail.get('kind'), 'http_status': detail.get('http_status', transport['http_status']),
                  **{k: detail.get(k) for k in ('provider_code','provider_type','provider_message')}})
        raise PipelineServiceError('judgment_'+stage+'_failed') from None
    finally:
        gateway.open = original_open
        raw_body = received['body']
        text = raw_body.decode('utf-8', 'replace').replace(gateway.key, '[REDACTED]')
        text = re.sub(r'(?i)(bearer\s+|sk-)[A-Za-z0-9_\-]+', '[REDACTED]', text)
        try:
            json.loads(raw_body)
            parse_state = 'json'
        except (ValueError, UnicodeError):
            parse_state = 'invalid_json' if received['seen'] else 'no_response'
        if received['read_state'] == 'failed_partial':
            parse_state = 'partial_body'
        elif received['read_state'] == 'failed_no_capture':
            parse_state = 'body_read_failed'
        elif received['headers_seen'] and not received['seen']:
            parse_state = 'body_unread'
        transport.update(response_received=received['headers_seen'], response_parse_state=parse_state,
                         body_read_state=received['read_state'], body_read_error_type=received['read_error_type'],
                         timing=deepcopy(getattr(gateway, 'last_transport_timing', None)))
        if received['seen']:
            store.put(artifacts+'response-capture.json', {
                'request_sha256': request_hash, 'http_status': transport['http_status'],
                'parse_state': parse_state, 'received_prefix_sha256': hashlib.sha256(raw_body).hexdigest(),
                'captured_bytes': len(raw_body), 'read_limit_reached': received['read_limit_reached'],
                'body_read_state': received['read_state'], 'body_read_error_type': received['read_error_type'],
                'body_utf8_redacted': text,
                'scope': 'Bounded received response bytes decoded with replacement and credential redaction. No-response failures have no capture artifact.'})
        store.put(artifacts+'transport.json', transport)
        if gateway.last_response is not None:
            store.put(artifacts+'response.json', gateway.last_response)
    result = {'schema_version': '3.1', 'integration_version': VERSION, 'job_id': job, 'attempt': int(attempt),
              **value, 'judgment_status': 'completed', 'context_key': key,
              'context_sha256': envelope['model_context_sha256'], 'request_sha256': request_hash,
              'model': gateway.model, 'source': 'model', 'coverage': envelope['coverage'],
              'created_at': datetime.now(timezone.utc).isoformat()}
    store.put(final_key, result, exclusive=True)
    return {'job_id': job, 'attempt': int(attempt), 'verdict': value['verdict'],
            'judgment_status': 'completed', 'judgment_key': final_key}


def handler(event, aws_context=None):
    role = os.environ['EVIDENCE_ROLE']
    with invocation(event, aws_context, role):
        return _handle(event, role)


def _handle(event, role):
    from .aws_clients import get_s3_client
    store = Store(get_s3_client(), os.environ.get('OUTPUT_BUCKET', os.environ.get('BUCKET_NAME', '')))
    if role in ('l0', 'l1', 'l23'):
        with span('bootstrap.legacy_import'):
            import legacy_handler
        return {'l0': l0, 'l1': l1, 'l23': l23}[role](event, legacy_handler, store)
    if role == 'context':
        if event.get('operation') == 'activity':
            return activity(event, store)
        if event.get('operation') == 'activity_context':
            return activity_context(event, store, max_bytes=int(os.environ.get('CONTEXT_MAX_BYTES', '400000')))
        if event.get('operation') not in (None, 'context'):
            raise ValueError('unknown_context_operation')
        return context(event, store, max_bytes=int(os.environ.get('CONTEXT_MAX_BYTES', '400000')))
    if role == 'activity':
        return activity(event, store)
    if role != 'judgment':
        raise ValueError('unknown_evidence_role')
    def make_gateway():
        # Only Gate's frozen, hashed server choice can override deployment defaults.
        # Revalidate against the configured allowlist; never silently fall back.
        selected = event.get('model_selection')
        profile = None
        if selected not in (None, {}):
            from .model_choices import validate_selection
            if os.environ.get('EVIDENCE_RESULT_CONTRACT') != 'fast-result-1':
                raise ValueError('model_selection_requires_fast_result_contract')
            profile = validate_selection(selected)['profile']
        provider = profile['provider'] if profile else os.environ.get('JUDGMENT_PROVIDER', 'anthropic')
        model = profile['model'] if profile else os.environ['JUDGMENT_MODEL']
        if provider == 'bedrock':
            if os.environ.get('EVIDENCE_RESULT_CONTRACT') != 'fast-result-1':
                raise ValueError('bedrock_requires_fast_result_contract')
            from .bedrock_gateway import BedrockAnthropicGateway
            return BedrockAnthropicGateway(model,
                region=os.environ.get('AWS_REGION'),
                timeout=profile['timeout'] if profile else float(os.environ.get('LLM_TIMEOUT_SECONDS', '120')),
                max_tokens=profile['max_tokens'] if profile else int(os.environ.get('JUDGMENT_MAX_TOKENS', '8192')),
                output_effort=profile['output_effort'] if profile else os.environ.get('ANTHROPIC_OUTPUT_EFFORT') or None)
        if provider != 'anthropic':
            raise ValueError('unsupported_judgment_provider')
        import boto3
        from .gateway import AnthropicGateway
        secret = boto3.client('secretsmanager').get_secret_value(SecretId=os.environ['LLM_SECRET_ID'])['SecretString'].strip()
        return AnthropicGateway(os.environ['ANTHROPIC_BASE_URL'], secret, model,
                                 timeout=profile['timeout'] if profile else float(os.environ.get('LLM_TIMEOUT_SECONDS', '50')),
                                 max_tokens=profile['max_tokens'] if profile else int(os.environ.get('JUDGMENT_MAX_TOKENS',
                                                '8192' if os.environ.get('EVIDENCE_RESULT_CONTRACT') == 'fast-result-1' else '1600')),
                                 omit_temperature=profile['omit_temperature'] if profile else os.environ.get('ANTHROPIC_OMIT_TEMPERATURE', '0') == '1',
                                 output_effort=profile['output_effort'] if profile else os.environ.get('ANTHROPIC_OUTPUT_EFFORT') or None)
    if os.environ.get('EVIDENCE_RESULT_CONTRACT') == 'fast-result-1':
        from .aws_fast_result import run_judgment
        return run_judgment(event, store, make_gateway)
    return judgment(event, store, make_gateway())
