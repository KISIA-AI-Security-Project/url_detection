"""Explicit Bedrock Messages transport for the fast-result contract."""
import json
import re
from time import monotonic

from .gateway import AnthropicGateway, JudgmentServiceError
from .performance import span


class BedrockAnthropicGateway:
    def __init__(self, model, *, client=None, region=None, timeout=120,
                 max_tokens=8192, output_effort='high'):
        if not isinstance(model, str) or not model.strip():
            raise ValueError('explicit_bedrock_model_required')
        if output_effort not in (None, 'low', 'medium', 'high', 'xhigh', 'max'):
            raise ValueError('unsupported_output_effort')
        if timeout <= 0 or type(max_tokens) is not int or max_tokens <= 0:
            raise ValueError('invalid_bedrock_timeout_or_budget')
        if client is None:
            from .aws_clients import get_bedrock_client
            client = get_bedrock_client(region=region, timeout=timeout)
        self.client, self.model = client, model
        self.max_tokens, self.output_effort = max_tokens, output_effort
        self.last_request_body = self.last_response = self.last_transport_timing = None

    def _payload(self, system, user):
        payload = {'anthropic_version': 'bedrock-2023-05-31',
                   'max_tokens': self.max_tokens, 'system': system,
                   'messages': [{'role': 'user', 'content': user}]}
        if self.output_effort is not None:
            payload['output_config'] = {'effort': self.output_effort}
        return payload

    def __call__(self, system, user):
        self.last_response = self.last_transport_timing = None
        with span('judgment.request_encode'):
            self.last_request_body = json.dumps(self._payload(system, user),
                ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        started = monotonic()
        try:
            # SDK request plus bounded response read/close, not pure model inference.
            with span('judgment.provider_transport'):
                response = self.client.invoke_model(modelId=self.model,
                    body=self.last_request_body, contentType='application/json', accept='application/json')
                stream = response['body']
                try:
                    body = stream.read(131073)
                finally:
                    stream.close()
        except Exception as exc:
            # SDK errors contain provider details; preserve only classification
            # here. A failed transport must never become an UNKNOWN verdict.
            code = getattr(exc, 'response', {}).get('Error', {}).get('Code', type(exc).__name__)
            kind = {'AccessDeniedException': 'permission_denied',
                    'ThrottlingException': 'rate_limited',
                    'ModelTimeoutException': 'request_timeout',
                    'ReadTimeoutError': 'request_timeout'}.get(code, 'bedrock_request_failed')
            raise JudgmentServiceError(kind, provider_code=code) from None
        finally:
            self.last_transport_timing = {'provider_seconds': round(monotonic() - started, 6),
                                          'requested_model': self.model, 'provider': 'bedrock'}
        if len(body) > 131072:
            raise JudgmentServiceError('response_size_limit')
        try:
            with span('judgment.response_decode'):
                self.last_response = json.loads(body)
                text = AnthropicGateway._text(self, self.last_response)
                if text.startswith('```'):
                    match = re.fullmatch(r'```(?:json)?\s*(\{.*\})\s*```', text, re.DOTALL)
                    if not match:
                        raise ValueError('invalid_json_fence')
                    text = match[1]
                value = json.loads(text)
                if not isinstance(value, dict):
                    raise ValueError('expected_object')
                return value
        except (ValueError, TypeError, KeyError, IndexError, AttributeError):
            raise JudgmentServiceError('response_format_invalid') from None
