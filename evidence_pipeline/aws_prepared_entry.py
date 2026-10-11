"""Optional deployment entry: prepare required tools before accepting requests.

Preparation remains visible as Lambda INIT. It does not run a URL scan or cache
request artifacts. Benchmarks must compare INIT plus invocation, not INIT alone.
"""
import importlib
import os

from .aws_clients import get_s3_client
from .aws_runtime import handler


def prepare(role):
    if role not in ('l0', 'l1', 'l23', 'context', 'activity', 'judgment'):
        raise ValueError('unsupported_prepared_role')
    get_s3_client()
    if role in ('l0', 'l1', 'l23'):
        importlib.import_module('legacy_handler')
    if role == 'l23':
        importlib.import_module('url_collector.ssrf')
        importlib.import_module('unified_scanner')
        importlib.import_module('unified_scanner.config')
        importlib.import_module('l2_scanner.config.tuning')
    if role in ('context', 'activity'):
        importlib.import_module('evidence_pipeline.url_activity')
    if role == 'context':
        importlib.import_module('evidence_pipeline.aws_fast_result')
        importlib.import_module('evidence_pipeline.fast_context')
    if role == 'judgment':
        importlib.import_module('evidence_pipeline.aws_fast_result')
        importlib.import_module('evidence_pipeline.fast_judgment')
        if os.environ.get('JUDGMENT_PROVIDER', 'anthropic') == 'bedrock':
            importlib.import_module('evidence_pipeline.bedrock_gateway')
            from .aws_clients import get_bedrock_client
            get_bedrock_client(region=os.environ.get('AWS_REGION'),
                              timeout=float(os.environ.get('LLM_TIMEOUT_SECONDS', '120')))
        else:
            importlib.import_module('evidence_pipeline.gateway')


prepare(os.environ['EVIDENCE_ROLE'])
