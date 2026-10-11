"""Fast result contract on the existing immutable S3 job/attempt store."""
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from hashlib import sha256
import json

from .fast_public import VERSION, make_public_result, validate_public_result
from .records import digest
from .performance import span


def keys(job, attempt):
    prefix = f'records/{job}/{attempt}/fast/'
    return {name: prefix + filename for name, filename in {
        'context': 'context.json', 'pending': 'pending.json', 'result': 'result.json',
        'judgment': 'judgment.json', 'handoff': 'deep-handoff.json',
        'claim': 'request-claim.json', 'request': 'model-request.json',
        'response': 'provider-response.json', 'diagnostics': 'link-diagnostics.json',
        'failure': 'service-failure.json'}.items()}


def persist_context(event, store, records, raws, refs, decision, *, max_bytes=400_000, native=None):
    from .aws_runtime import identity, record_key, VERSION as RUNTIME_VERSION
    job, attempt, url = identity(event)
    paths = keys(job, attempt)
    if native is None:
        native = store.get(record_key(job, attempt, 'l3'))['observation']
    storage_refs = {layer: {**reference, 'record_root_pointer': '/evidence_record', 'raw_root_pointer': ''}
                    for layer, reference in refs.items()}
    with span('bootstrap.builder_import'):
        from .fast_context import build_fast_context
    with span('context.build'):
        context = build_fast_context(records, raws, native=native, artifact_refs=storage_refs, max_bytes=max_bytes)
    store.put(paths['context'], context)
    skip = decision.get('can_skip_judgment') is True
    public = make_public_result(job, attempt, context=context, status='not_requested' if skip else 'pending')
    store.put(paths['result'] if skip else paths['pending'], public)
    envelope = {'integration_version': RUNTIME_VERSION, 'result_contract_version': VERSION,
                'job_id': job, 'attempt': int(attempt), 'input_url': url,
                'analysis_status': 'NOT_REQUESTED' if skip else 'COMPLETED',
                'fast_context_key': paths['context'], 'context_revision': context['context_revision'],
                'model_context_sha256': context['model_body_sha256'],
                'url_activity_key': f'records/{job}/{attempt}/final/url-activity.json',
                'url_activity_sha256': digest(decision)}
    final_key = record_key(job, attempt, 'final')
    store.put(final_key, envelope)
    return {'job_id': job, 'attempt': int(attempt), 'final_key': final_key,
            'context_sha256': context['model_body_sha256'], 'analysis_status': envelope['analysis_status'],
            'result_contract_version': VERSION, 'context_revision': context['context_revision'],
            'fast_result_key': paths['result'] if skip else paths['pending'],
            'url_activity_key': envelope['url_activity_key'], 'url_activity_sha256': digest(decision),
            'url_activity_state': decision['state'], 'skip_judgment': skip}


def _event_result(public, paths):
    result = {'job_id': public['job_id'], 'attempt': public['attempt'],
              'result_contract_version': VERSION, 'judgment_status': public['judgment_status'],
              'fast_result_key': paths['result'], 'judgment_key': paths['judgment'],
              'context_revision': public['context_revision'], 'result_revision': public['result_revision']}
    if public['judgment'] is not None:
        result['verdict'] = public['judgment']['verdict']
    return result


def _submit_io(pool, function, *args, **kwargs):
    # Each operation gets its own context, sharing only the invocation's
    # thread-safe trace. The pool is always joined before leaving this call.
    return pool.submit(copy_context().run, function, *args, **kwargs)


def run_judgment(event, store, gateway_factory):
    """Exactly one provider attempt; a new attempt is required after service failure."""
    with span('bootstrap.judgment_import'):
        from .aws_runtime import identity, record_key, PipelineServiceError
        from .fast_judgment import PROMPT, link_judgment, validate_response
        from .gateway import JudgmentServiceError
    job, attempt, url = identity(event)
    paths = keys(job, attempt)
    if event.get('context_key') != record_key(job, attempt, 'final'):
        raise PipelineServiceError('explicit_builder_key_required')
    envelope = store.get(event['context_key'])
    if (envelope.get('job_id') != job or str(envelope.get('attempt')) != attempt or
            envelope.get('input_url') != url or envelope.get('result_contract_version') != VERSION or
            envelope.get('fast_context_key') != paths['context'] or
            envelope.get('analysis_status') != 'COMPLETED'):
        raise PipelineServiceError('fast_context_identity_mismatch')
    with span('judgment.load_inputs'), ThreadPoolExecutor(max_workers=3) as pool:
        context_read = _submit_io(pool, store.get, paths['context'])
        activity_read = _submit_io(pool, lambda: store.get(envelope['url_activity_key']))
        result_read = _submit_io(pool, store.get, paths['result'], optional=True)
        # Consume and validate in the original order, regardless of completion
        # order. No claim or provider call can precede these checks.
        context = context_read.result()
        if (context.get('job_id') != job or str(context.get('attempt')) != attempt or
                context.get('context_revision') != envelope.get('context_revision') or
                sha256(context['model_body'].encode('utf-8')).hexdigest() != envelope['model_context_sha256'] or
                event.get('context_sha256') != envelope['model_context_sha256']):
            raise PipelineServiceError('fast_context_binding_mismatch')
        decision = activity_read.result()
        if digest(decision) != envelope['url_activity_sha256'] or decision.get('can_skip_judgment') is not False:
            raise PipelineServiceError('fast_activity_binding_mismatch')
        existing = result_read.result()
    from .model_choices import bind_model_selection
    bind_model_selection(event, store, job, attempt, existing_result=existing)
    if existing is not None:
        validate_public_result(existing, job_id=job, attempt=attempt)
        if existing['context_revision'] != context['context_revision']:
            raise PipelineServiceError('existing_result_context_mismatch')
        return _event_result(existing, paths)
    # Atomic claim prevents duplicate charged calls on Lambda/SFN retry.
    store.put(paths['claim'], {'context_revision': context['context_revision']}, exclusive=True)
    gateway = None
    response_received = False
    response, failure, status = None, None, 'accepted'
    try:
        with span('judgment.gateway_setup'):
            gateway = gateway_factory()
        with span('judgment.request_prepare'):
            expected = json.dumps(gateway._payload(PROMPT, context['model_body']),
                                  ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        store.put_bytes(paths['request'], expected)
        response = gateway(PROMPT, context['model_body'])
        response_received = True
        with span('judgment.response_validate'):
            if gateway.last_request_body != expected:
                raise PipelineServiceError('actual_model_request_changed')
            response = validate_response(response)
    except JudgmentServiceError as exc:
        status = 'invalid' if exc.detail['kind'] in {
            'response_format_invalid', 'response_incomplete', 'response_size_limit'} else 'failed'
        failure = {'kind': exc.detail['kind']}
    except ValueError as exc:
        status, failure = ('invalid' if response_received else 'failed'), {'kind': str(exc)}
    except Exception as exc:
        status, failure = 'failed', {'kind': type(exc).__name__}
    provider_response = gateway.last_response if gateway is not None else None
    if status == 'accepted':
        with span('judgment.persist_outputs'), ThreadPoolExecutor(max_workers=4) as pool:
            writes = []
            if provider_response is not None:
                writes.append(_submit_io(pool, store.put, paths['response'], provider_response))
            try:
                with span('judgment.link'):
                    public_judgment, diagnostics = link_judgment(response, context)
                writes.append(_submit_io(pool, store.put, paths['diagnostics'],
                    {'context_revision': context['context_revision'], 'items': diagnostics}))
                writes.append(_submit_io(pool, store.put, paths['judgment'],
                    {'schema_version': VERSION, 'job_id': job, 'attempt': int(attempt),
                     'context_revision': context['context_revision'], 'response': response}))
                with span('judgment.public_build'):
                    public = make_public_result(job, attempt, context=context, status=status, judgment=public_judgment)
                # These immutable artifacts are internal. Public result is the
                # commit point, after every prerequisite has been stored.
                writes.append(_submit_io(pool, store.put, paths['handoff'],
                    {'schema_version': 'fast-deep-handoff-1', 'job_id': job,
                     'attempt': int(attempt), 'input_url': url,
                     'context_revision': context['context_revision'], 'result_revision': public['result_revision'],
                     'context_key': paths['context'], 'judgment_key': paths['judgment'],
                     'screenshot': None}))
            finally:
                # Keep the original failure priority and finish all submitted
                # operations before returning or raising. Failed staging never
                # publishes an accepted result or permits a second model call.
                for write in writes:
                    write.result()
    else:
        if provider_response is not None:
            store.put(paths['response'], provider_response)
        store.put(paths['failure'], {'job_id': job, 'attempt': int(attempt),
                                    'judgment_status': status, 'failure': failure})
        with span('judgment.public_build'):
            public = make_public_result(job, attempt, context=context, status=status, judgment=None)
    store.put(paths['result'], public)
    return _event_result(public, paths)


def load_deep_input(request, store):
    """Internal server adapter, invoked after the user's deep-analysis request."""
    from .aws_runtime import identity, PipelineServiceError
    from .request_options import normalize_request_text
    request_text = normalize_request_text(request.get('request_text', ''))
    job, attempt, _ = identity(request, require_url=False)
    paths = keys(job, attempt)
    public = validate_public_result(store.get(paths['result']), job_id=job, attempt=attempt)
    if (not public['deep_analysis']['available'] or
            request.get('context_revision') != public['context_revision'] or
            request.get('result_revision') != public['result_revision']):
        raise PipelineServiceError('deep_request_revision_mismatch')
    handoff = store.get(paths['handoff'])
    if (handoff.get('job_id') != job or str(handoff.get('attempt')) != attempt or
            handoff.get('context_revision') != public['context_revision'] or
            handoff.get('result_revision') != public['result_revision'] or
            handoff.get('context_key') != paths['context'] or handoff.get('judgment_key') != paths['judgment']):
        raise PipelineServiceError('deep_handoff_identity_mismatch')
    context, judgment = store.get(paths['context']), store.get(paths['judgment'])
    if (context.get('context_revision') != public['context_revision'] or
            judgment.get('context_revision') != public['context_revision']):
        raise PipelineServiceError('deep_input_context_mismatch')
    prepared = {'job_id': job,
            'initial_findings': {'requested_url': handoff['input_url'], 'builder_context': context['model_body'],
                                 'confirmed_facts': deepcopy(context['details']),
                                 'builder_record_mapping': deepcopy(context['item_mapping']),
                                 'source_mapping': deepcopy(context['source_mapping']),
                                 'attempt': int(attempt), 'context_revision': public['context_revision']},
            'previous_judgment': deepcopy(judgment['response'])}
    if request_text:
        prepared['request_text'] = request_text
    return prepared


async def run_requested_deep_analysis(request, fast_store, *, l4_store, publisher, registry,
                                      model_name, executor_model, execution_limits,
                                      files=None, run_config=None, runner=None):
    """Server-side bridge after authorization and an explicit user request."""
    prepared = load_deep_input(request, fast_store)
    if runner is None:
        from l4_orchestrator.sdk_runtime import run_l4
        runner = run_l4
    return await runner(**prepared, store=l4_store, publisher=publisher, registry=registry,
                        model_name=model_name, executor_model=executor_model,
                        execution_limits=execution_limits, files=files, run_config=run_config)
