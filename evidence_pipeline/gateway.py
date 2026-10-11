"""판정 서비스 연결. 서비스 오류를 URL 판정과 구분한다."""
import json
import hashlib
from copy import deepcopy
import re
import urllib.error
import urllib.request
from urllib.parse import urlsplit


class JudgmentServiceError(RuntimeError):
    def __init__(self, kind, **detail):
        self.detail={'kind':kind, **detail}
        super().__init__(kind)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class AnthropicGateway:
    endpoint='/v1/messages'
    allow_loopback_http=False

    def __init__(self, base_url, api_key, model, *, timeout=90, max_tokens=1600, opener=None,
                 omit_temperature=False, output_effort=None):
        parsed=urlsplit(base_url)
        local_http=self.allow_loopback_http and parsed.scheme=='http' and parsed.hostname in {'localhost','127.0.0.1','::1'}
        if (parsed.scheme!='https' and not local_http) or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError('Gateway must be an HTTPS origin/path without credentials, query or fragment')
        if not api_key.strip() or not model.strip(): raise ValueError('Missing API key or model')
        if type(omit_temperature) is not bool:
            raise ValueError('omit_temperature must be a boolean')
        if output_effort is not None and output_effort not in {'low','medium','high','xhigh','max'}:
            raise ValueError('unsupported_output_effort')
        self.url=base_url.rstrip('/')+self.endpoint
        self.key,self.model,self.timeout,self.max_tokens=api_key,model,timeout,max_tokens
        self.omit_temperature,self.output_effort=omit_temperature,output_effort
        self.open=opener or urllib.request.build_opener(NoRedirect()).open
        self.last_response=None
        self.last_request_body=None
        self.last_budget_check=None

    def _preflight(self, system, user):
        pass

    def _payload(self,system,user):
        payload={'model':self.model,'max_tokens':self.max_tokens}
        # Explicit provider settings preserve legacy requests and never infer or
        # replace a model ID. New Claude models reject temperature=0.
        if not self.omit_temperature:payload['temperature']=0
        payload.update(system=system,messages=[{'role':'user','content':user}])
        if self.output_effort is not None:payload['output_config']={'effort':self.output_effort}
        return payload

    def _headers(self):
        return {'Authorization':'Bearer '+self.key,'anthropic-version':'2023-06-01',
                'content-type':'application/json','User-Agent':'team5-url-analysis/1.0'}

    def _text(self,envelope):
        if envelope.get('stop_reason')!='end_turn':raise JudgmentServiceError('response_incomplete',stop_reason=envelope.get('stop_reason'))
        return '\n'.join(b.get('text','') for b in envelope['content'] if b.get('type')=='text').strip()

    def __call__(self, system, user):
        self.last_response=None
        self.last_request_body=None
        self.last_budget_check=None
        self._preflight(system,user)
        # Preserve schema-property order: the structured generation backend can
        # follow it. Do not canonical-sort the schema for hashing or transport.
        body=json.dumps(self._payload(system,user),ensure_ascii=False,separators=(',', ':')).encode()
        # Preserve the exact JSON sent, without authentication headers. Keep this
        # even when the provider fails, so experiments remain reproducible.
        self.last_request_body=body
        if self.last_budget_check is not None:self.last_budget_check['judgment_request_attempted']=True
        request=urllib.request.Request(self.url,data=body,headers=self._headers(),method='POST')
        try:
            with self.open(request,timeout=self.timeout) as response:
                body=response.read(131073)
        except urllib.error.HTTPError as exc:
            text=exc.read(8192).decode('utf-8','replace').replace(self.key,'[REDACTED]')
            text=re.sub(r'(?i)(bearer\s+|sk-)[A-Za-z0-9_\-]+','[REDACTED]',text)
            try:
                detail=json.loads(text);detail=detail.get('error',detail)
            except ValueError: detail={}
            detail=detail if isinstance(detail,dict) else {}
            code=detail.get('code'); error_type=detail.get('type')
            kind='quota_exceeded' if code=='key_quota_exceeded' or error_type=='insufficient_credits' else {401:'authentication_failed',403:'permission_denied',402:'payment_required',429:'rate_limited'}.get(exc.code,'http_failure')
            raise JudgmentServiceError(kind,http_status=exc.code,provider_code=code,provider_type=error_type,provider_message=str(detail.get('message',''))[:1500]) from None
        except (TimeoutError,urllib.error.URLError,ConnectionError,OSError) as exc:
            reason=getattr(exc,'reason',exc)
            raise JudgmentServiceError('request_timeout' if isinstance(reason,TimeoutError) else 'connection_failed',error_type=type(reason).__name__) from None
        if len(body)>131072: raise JudgmentServiceError('response_size_limit')
        try:
            envelope=json.loads(body)
            self.last_response=json.loads(json.dumps(envelope,ensure_ascii=False).replace(self.key,'[REDACTED]'))
            text=self._text(envelope)
            if text.startswith('```'):
                match=re.fullmatch(r'```(?:json)?\s*(\{.*\})\s*```',text,re.DOTALL)
                if not match: raise ValueError('Invalid JSON fence')
                text=match[1]
            value=json.loads(text)
            if not isinstance(value,dict): raise ValueError('Expected object')
            return value
        except (ValueError,TypeError,KeyError,IndexError,AttributeError):
            raise JudgmentServiceError('response_format_invalid') from None


class OpenAICompatibleGateway(AnthropicGateway):
    """HTTPS API or an existing inference server on the same host."""
    endpoint='/v1/chat/completions'
    allow_loopback_http=True

    def __init__(self,*args,disable_thinking=False,structured_output=False,max_context_tokens=None,**kwargs):
        super().__init__(*args,**kwargs)
        self.disable_thinking=disable_thinking
        self.structured_output=structured_output
        if max_context_tokens is not None and (type(max_context_tokens) is not int or max_context_tokens<=0):
            raise ValueError('max_context_tokens must be a positive integer')
        self.max_context_tokens=max_context_tokens
        self._prepared_budget=None

    def _budget_identity(self,system,user):
        return (self.model,self.max_tokens,self.max_context_tokens,self.disable_thinking,
                hashlib.sha256((system+'\0'+user).encode()).hexdigest())

    def prepare_context(self,system,context):
        """Choose a fitting representation without removing evidence or judging it."""
        self.last_response=None
        self.last_request_body=None
        self.last_budget_check=None
        if self.max_context_tokens is None:return context
        from .context_inventory import present,restore
        attempts=[]
        self._prepared_budget=None
        for name in ['explicit_relationships','lossless_inventory']:
            if name=='lossless_inventory' and 'inventory_encoding_v2' in context:
                break
            candidate=context if name=='explicit_relationships' else present(restore(context))
            if name=='lossless_inventory':
                if candidate==context:break
                if json.dumps(restore(candidate),sort_keys=True)!=json.dumps(restore(context),sort_keys=True):raise ValueError('inventory_restore_mismatch')
            user=json.dumps(candidate,ensure_ascii=False,separators=(',', ':'))
            try:self._preflight(system,user)
            except JudgmentServiceError as exc:
                attempts.append({'presentation':name,'user_sha256':hashlib.sha256(user.encode()).hexdigest(),
                                 **deepcopy(self.last_budget_check)})
                if exc.detail['kind']!='context_window_exceeded':
                    self.last_budget_check.update(presentation=name,selection_attempts=attempts)
                    raise
            else:
                attempts.append({'presentation':name,'user_sha256':hashlib.sha256(user.encode()).hexdigest(),
                                 **deepcopy(self.last_budget_check)})
                self.last_budget_check.update(presentation=name,selection_attempts=attempts)
                self._prepared_budget=(self._budget_identity(system,user),deepcopy(self.last_budget_check))
                return candidate
        self.last_budget_check['selection_attempts']=attempts
        raise JudgmentServiceError('context_window_exceeded',selection_attempts=attempts)

    def _preflight(self,system,user):
        if self.max_context_tokens is None:
            return
        if self._prepared_budget and self._prepared_budget[0]==self._budget_identity(system,user):
            self.last_budget_check=deepcopy(self._prepared_budget[1])
            return
        payload={'model':self.model,'messages':[{'role':'system','content':system},{'role':'user','content':user}],
                 'add_generation_prompt':True}
        if self.disable_thinking:payload['chat_template_kwargs']={'enable_thinking':False}
        body=json.dumps(payload,ensure_ascii=False,separators=(',', ':')).encode()
        # Explicit opt-in for inference services exposing the verified /tokenize
        # endpoint. A count failure is not treated as zero tokens or a verdict.
        url=self.url.removesuffix(self.endpoint)+'/tokenize'
        request=urllib.request.Request(url,data=body,headers=self._headers(),method='POST')
        try:
            with self.open(request,timeout=self.timeout) as response:data=response.read(2_000_001)
            if len(data)>2_000_000:raise ValueError('tokenization response size limit')
            count=json.loads(data).get('count')
            if type(count) is not int or count<0:raise ValueError('missing valid token count')
        except (ValueError,TypeError,AttributeError,urllib.error.HTTPError,urllib.error.URLError,OSError) as exc:
            self.last_budget_check={'status':'failed','error_type':type(exc).__name__,'judgment_request_attempted':False}
            raise JudgmentServiceError('tokenization_failed',error_type=type(exc).__name__) from None
        fits=count+self.max_tokens<=self.max_context_tokens
        self.last_budget_check={'status':'counted','prompt_tokens':count,'reserved_output_tokens':self.max_tokens,
                                'max_context_tokens':self.max_context_tokens,'fits':fits,
                                'judgment_request_attempted':False}
        if not fits:
            raise JudgmentServiceError('context_window_exceeded',prompt_tokens=count,
                                       reserved_output_tokens=self.max_tokens,max_context_tokens=self.max_context_tokens)

    def _payload(self,system,user):
        payload={'model':self.model,
                 'messages':[{'role':'system','content':system},{'role':'user','content':user}],
                 'max_tokens':self.max_tokens,'temperature':0}
        if self.disable_thinking:payload['chat_template_kwargs']={'enable_thinking':False}
        if self.structured_output:
            from .judgment_contract import response_format
            payload['response_format']=response_format(json.loads(user))
        return payload

    def _headers(self):
        return {'Authorization':'Bearer '+self.key,'content-type':'application/json'}

    def _text(self,envelope):
        choice=envelope['choices'][0]
        if choice.get('finish_reason')!='stop':raise JudgmentServiceError('response_incomplete',stop_reason=choice.get('finish_reason'))
        return choice['message']['content'].strip()
