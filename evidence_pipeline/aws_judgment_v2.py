"""Isolated Judgment v2 adapter for the DNS-parallel Step Functions path."""
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import urllib.error

from .aws_runtime import PipelineServiceError, Store, VERSION, identity, record_key
from .gateway import AnthropicGateway, JudgmentServiceError, NoRedirect
from .judgment_contract_v2 import persist_judgment_output_v2
from .judgment_view_v2 import build_judgment_view_v2
from .phase_transport import PhaseTrace, traced_opener
from .pipeline import render_context
from .records import digest


PROMPT = (Path(__file__).parent / 'judgment_prompt_v2.txt').read_text(encoding='utf-8')
LEGACY_STRUCTURED_PROMPT = (Path(__file__).parent /
                            'judgment_prompt_v2_structured_legacy.txt').read_text(encoding='utf-8')


class JudgmentV2Gateway(AnthropicGateway):
    def __init__(self, *args, view, **kwargs):
        supplied_opener = kwargs.get('opener')
        super().__init__(*args, **kwargs)
        self.view = view
        self.phase_trace = PhaseTrace()
        if supplied_opener is None:
            self.open = traced_opener(self.phase_trace, NoRedirect())

    # Use the normal Messages JSON response path. Per-input evidence enums made
    # a different constrained-output schema for each fact set; observed first-use
    # schemas exceeded the 50-second deadline, consistent with compilation cost.
    # The prompt defines the output shape, and persist_judgment_output_v2 still
    # checks the exact allowed fields, verdict, references and grounding before
    # any verdict is published. Never publish an unvalidated model response.

    def _headers(self):
        headers = super()._headers()
        headers['user-agent'] = 'team5-judgment-lambda/1.0'
        return headers


def _call_with_capture(gateway, user, store, prefix, request_sha):
    """Retain bounded redacted response bytes even when the provider JSON is invalid."""
    transport = {'endpoint': gateway.url, 'requested_model': gateway.model,
                 'request_sha256': request_sha, 'http_status': None}
    received = {'body': b'', 'seen': False, 'headers_seen': False,
                'read_state': 'not_started', 'read_error_type': None}
    original_open = gateway.open

    def capture(data):
        received['body'] = data[:131073]
        received['seen'] = True

    class CapturedResponse:
        def __init__(self, response):
            self.response = response

        def __enter__(self):
            self.response.__enter__()
            return self

        def __exit__(self, *args):
            return self.response.__exit__(*args)

        def read(self, size=-1):
            try:
                data = self.response.read(size)
            except Exception as exc:
                gateway.phase_trace.failed(exc)
                partial = getattr(exc, 'partial', None)
                received['read_state'] = 'failed_partial' if isinstance(partial, (bytes, bytearray)) else 'failed_no_capture'
                received['read_error_type'] = type(exc).__name__
                if isinstance(partial, (bytes, bytearray)):
                    capture(bytes(partial))
                raise
            capture(data)
            received['read_state'] = 'completed'
            return data

    def open_captured(request, **kwargs):
        try:
            response = original_open(request, **kwargs)
        except urllib.error.HTTPError as exc:
            transport['http_status'] = exc.code
            received['headers_seen'] = True
            try:
                data = exc.read(8192)
                capture(data)
                received['read_state'] = 'completed'
            finally:
                exc.close()
            raise urllib.error.HTTPError(exc.url, exc.code, exc.msg,
                                         exc.headers, io.BytesIO(data)) from None
        except Exception as exc:
            transport['http_status'] = getattr(exc, 'code', None)
            raise
        transport['http_status'] = getattr(response, 'status', None)
        received['headers_seen'] = True
        return CapturedResponse(response)

    gateway.open = open_captured
    try:
        return gateway(PROMPT, user)
    finally:
        gateway.open = original_open
        raw = received['body']
        try:
            json.loads(raw)
            parse_state = 'json'
        except (ValueError, UnicodeError):
            parse_state = 'invalid_json' if received['seen'] else 'no_response'
        if received['read_state'] == 'failed_partial':
            parse_state = 'partial_body'
        elif received['read_state'] == 'failed_no_capture':
            parse_state = 'body_read_failed'
        elif received['headers_seen'] and not received['seen']:
            parse_state = 'body_unread'
        transport.update(response_received=received['headers_seen'],
                         response_parse_state=parse_state,
                         body_read_state=received['read_state'],
                         body_read_error_type=received['read_error_type'],
                         client_phase=gateway.phase_trace.snapshot())
        if received['seen']:
            redacted = raw.decode('utf-8', 'replace').replace(gateway.key, '[REDACTED]')
            redacted = re.sub(r'(?i)(bearer\s+|sk-)[A-Za-z0-9_\-]+', '[REDACTED]', redacted)
            store.put(prefix + 'response-capture.json', {
                'request_sha256': request_sha, 'http_status': transport['http_status'],
                'parse_state': parse_state, 'captured_bytes': len(raw),
                'received_prefix_sha256': hashlib.sha256(raw).hexdigest(),
                'body_utf8_redacted': redacted})
        store.put(prefix + 'transport.json', transport)
        if gateway.last_response is not None:
            store.put(prefix + 'response.json', gateway.last_response)


def judgment_v2(event, store, gateway_factory):
    if os.environ.get('EVIDENCE_RESULT_CONTRACT') == 'fast-result-1':
        from .aws_fast_result import run_judgment
        return run_judgment(event, store, lambda: gateway_factory(None))
    job, attempt, url = identity(event)
    context_key = record_key(job, attempt, 'final')
    if event.get('context_key') != context_key:
        raise PipelineServiceError('explicit_builder_key_required')
    envelope = store.get(context_key)
    if (envelope.get('integration_version'), envelope.get('job_id'), str(envelope.get('attempt')),
            envelope.get('input_url'), envelope.get('analysis_status')) != (
            VERSION, job, attempt, url, 'COMPLETED'):
        raise PipelineServiceError('context_identity_mismatch')
    decision = store.get(envelope.get('url_activity_key', ''))
    if (digest(decision) != envelope.get('url_activity_sha256') or
            decision.get('request_id') != job or str(decision.get('attempt')) != attempt or
            decision.get('input_url') != url):
        raise PipelineServiceError('activity_binding_mismatch')
    if decision.get('can_skip_judgment') or decision.get('state') in (
            'DNS_NAME_NONEXISTENT_AT_SCAN', 'URL_UNREACHABLE_AT_SCAN'):
        raise PipelineServiceError('judgment_forbidden_by_dns_activity')
    context = envelope['model_context']
    context_sha = hashlib.sha256(render_context(context).encode()).hexdigest()
    if (context_sha != envelope.get('model_context_sha256') or
            context_sha != event.get('context_sha256')):
        raise PipelineServiceError('context_hash_mismatch')
    view = build_judgment_view_v2(context)
    user = json.dumps(view, ensure_ascii=False, separators=(',', ':'))
    gateway = gateway_factory(view)
    request = json.dumps(gateway._payload(PROMPT, user), ensure_ascii=False,
                         separators=(',', ':')).encode()
    request_sha = hashlib.sha256(request).hexdigest()
    final_key = f'judgments/{job}/{attempt}.json'
    prefix = f'judgments/{job}/{attempt}/v2/'
    existing = store.get(final_key, optional=True)
    if existing is not None:
        if (existing.get('judgment_contract_version'), existing.get('job_id'),
                str(existing.get('attempt')), existing.get('context_sha256'),
                existing.get('request_sha256'), existing.get('judgment_status')) != (
                'fact-interpretation-selection-2', job, attempt, context_sha,
                request_sha, 'completed'):
            raise PipelineServiceError('existing_judgment_binding_mismatch')
        return {'job_id': job, 'attempt': int(attempt), 'verdict': existing['verdict'],
                'judgment_status': 'completed', 'judgment_key': final_key}
    if store.get(prefix + 'request-claim.json', optional=True) is not None:
        raise PipelineServiceError('prior_judgment_attempt_incomplete')
    store.put(prefix + 'request-claim.json', {
        'request_sha256': request_sha, 'context_sha256': context_sha,
        'model': gateway.model, 'judgment_contract_version': 'fact-interpretation-selection-2'},
        exclusive=True)
    store.put(prefix + 'view.json', view)
    store.put_bytes(prefix + 'request.json', request)
    try:
        selection = _call_with_capture(gateway, user, store, prefix, request_sha)
        if gateway.last_request_body != request:
            raise PipelineServiceError('gateway_wire_mismatch')
        processing = persist_judgment_output_v2(
            selection, view, lambda name, value: store.put(prefix + name, value))
        if processing['status'] != 'accepted':
            raise PipelineServiceError('judgment_v2_rejected:' + processing['rejection_code'])
    except Exception as exc:
        trace = gateway.phase_trace.snapshot()
        detail = getattr(exc, 'detail', {})
        original_error_code = str(exc)[:200]
        phase_error = None
        if (isinstance(exc, JudgmentServiceError) and
                detail.get('kind') in ('request_timeout', 'connection_failed') and
                trace['failure_phase'] in (
                    'dns_lookup', 'tcp_connect', 'proxy_tunnel', 'tls_handshake',
                    'request_write', 'response_headers', 'response_body')):
            code = 'model_api_' + trace['failure_phase'] + (
                '_timeout' if detail['kind'] == 'request_timeout' else '_connection_failed')
            phase_error = JudgmentServiceError(
                code, **{**{key: value for key, value in detail.items() if key != 'kind'},
                         'original_kind': detail['kind'],
                         'failure_phase': trace['failure_phase']})
            detail = phase_error.detail
        store.put(prefix + 'failure.json', {
            'judgment_status': 'failed', 'error_type': type(phase_error or exc).__name__,
            'error_code': str(phase_error or exc)[:200], 'request_sha256': request_sha,
            'kind': detail.get('kind'), 'http_status': detail.get('http_status'),
            'provider_code': detail.get('provider_code'),
            'original_error_code': original_error_code,
            'failure_phase': trace['failure_phase'],
            'exception_type': trace['exception_type'],
            'request_bytes_written': trace['request_bytes_written'],
            'response_headers_received': trace['response_headers_received'],
            'elapsed_ms': trace['elapsed_ms']})
        if phase_error is not None:
            raise phase_error from None
        raise
    consumer = processing['consumer']
    result = {
        'schema_version': 'judgment-v2-isolated-1', 'integration_version': VERSION,
        'judgment_contract_version': consumer['judgment_contract_version'],
        'job_id': job, 'attempt': int(attempt), 'input_url': url,
        'verdict': consumer['verdict'], 'judgment_status': 'completed',
        'processing_status': 'accepted',
        'consumer': consumer, 'context_key': context_key,
        'context_sha256': context_sha, 'request_sha256': request_sha,
        'view_key': prefix + 'view.json', 'view_sha256': digest(view),
        'source_evidence_sha256': view['source_accounting']['source_evidence_sha256'],
        'model': gateway.model, 'source': 'model', 'coverage': envelope['coverage'],
        'created_at': datetime.now(timezone.utc).isoformat()}
    store.put(final_key, result, exclusive=True)
    return {'job_id': job, 'attempt': int(attempt), 'verdict': consumer['verdict'],
            'judgment_status': 'completed', 'judgment_key': final_key}


def handler(event, aws_context=None):
    import boto3
    store = Store(boto3.client('s3'), os.environ.get('OUTPUT_BUCKET', os.environ.get('BUCKET_NAME', '')))
    def gateway(view):
        secret = boto3.client('secretsmanager').get_secret_value(
            SecretId=os.environ['LLM_SECRET_ID'])['SecretString'].strip()
        return JudgmentV2Gateway(
            os.environ['ANTHROPIC_BASE_URL'], secret, os.environ['JUDGMENT_MODEL'],
            view=view, timeout=float(os.environ.get('LLM_TIMEOUT_SECONDS', '60')),
            max_tokens=int(os.environ.get('JUDGMENT_MAX_TOKENS',
                           '8192' if os.environ.get('EVIDENCE_RESULT_CONTRACT') == 'fast-result-1' else '500')))
    return judgment_v2(event, store, gateway)
