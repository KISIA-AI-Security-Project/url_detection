"""Use one page collection in the isolated Lambda, with its existing L3 policy."""
from copy import deepcopy
from .performance import current_trace, span


def collect_outcomes(url, legacy):
    # Measure first-use imports separately from collection and analysis.
    with span('bootstrap.scanner_import'):
        from unified_scanner import UnifiedScanner
        from unified_scanner.config import UnifiedConfig
        from url_collector import CollectionPolicy
        from l2_scanner.config.tuning import HTTP_TIMEOUT_SECONDS, MAX_BODY_BYTES, MAX_REDIRECT_HOPS, USER_AGENT

    with span('bootstrap.scanner_config'):
        runtime = legacy.l3_runtime_from_env()
        detection_policy = legacy.l3_policy()
        # One shared request must obey both collectors' limits; layer-specific
        # certificate and external-script requests retain their existing settings.
        policy = CollectionPolicy(
            request_timeout_seconds=min(HTTP_TIMEOUT_SECONDS, runtime.request_timeout_seconds),
            max_redirects=min(MAX_REDIRECT_HOPS, runtime.max_redirects),
            max_body_bytes=min(MAX_BODY_BYTES, runtime.max_html_bytes),
            user_agent=USER_AGENT,
        )
        trace = current_trace()
        scanner = UnifiedScanner(UnifiedConfig(collection=policy, l3_runtime=runtime),
                                 detection_policy=detection_policy,
                                 timing_observer=trace.span if trace is not None else None)
    result = scanner.scan_url(url, budget_seconds=legacy.budget_seconds())
    errors = {row['layer'].lower(): row for row in result['errors']}
    outcomes = {}
    for layer in ('l2', 'l3'):
        native = result['layers'][layer]
        error = errors.get(layer)
        if native is None:
            native = {'target': {'original_url': url}, 'scan': {'status': 'failed'},
                      'producer_execution': {'state': 'failed', 'reason': 'shared_page_analysis_failed'},
                      'raw': {}, 'signals': [], 'errors': [{
                          'code': 'shared_page_analysis_failed', 'stage': 'analysis',
                          'impact_scope': 'analysis', 'error_type': error['error_type'],
                          'message': error['message']}]}
        native['shared_page_observation'] = deepcopy(result['collection'])
        # Preserve the actual collected bytes even when both analyzers fail.
        native.setdefault('raw', {})['shared_page'] = deepcopy(
            result['raw_snapshot'] if layer == 'l2' else result['collection'])
        outcomes[layer] = legacy.Outcome(result=native,
            timed_out=bool(error and error['error_type'] == 'LayerBudgetExceeded'),
            error=RuntimeError(error['message']) if error and error['error_type'] != 'LayerBudgetExceeded' else None)
    return outcomes
