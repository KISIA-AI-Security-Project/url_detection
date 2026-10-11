"""Input-window failures must not masquerade as URL judgments or API attempts."""
import io,json
import pytest
from evidence_pipeline.gateway import OpenAICompatibleGateway,JudgmentServiceError

@pytest.mark.parametrize('count,allowed',[(47152,True),(47153,False)])
def test_actual_token_count_reserves_output_before_judgment(count,allowed):
    calls=[]
    def opener(request,**kwargs):
        calls.append(request)
        if request.full_url.endswith('/tokenize'):
            payload=json.loads(request.data)
            assert payload['messages']==[{'role':'system','content':'기준'},{'role':'user','content':'증거'}]
            assert payload['chat_template_kwargs']=={'enable_thinking':False}
            return io.BytesIO(json.dumps({'count':count}).encode())
        return io.BytesIO(b'{"choices":[{"finish_reason":"stop","message":{"content":"{}"}}]}')
    gateway=OpenAICompatibleGateway('http://127.0.0.1:8000','test-key','test-model',
        opener=opener,disable_thinking=True,max_tokens=2000,max_context_tokens=49152)
    if allowed:
        assert gateway('기준','증거')=={}
        assert len(calls)==2 and gateway.last_request_body==calls[1].data
    else:
        with pytest.raises(JudgmentServiceError) as error:gateway('기준','증거')
        assert error.value.detail['kind']=='context_window_exceeded'
        assert len(calls)==1 and gateway.last_request_body is None and gateway.last_response is None
    assert gateway.last_budget_check['fits']==allowed
    assert gateway.last_budget_check['judgment_request_attempted']==allowed

@pytest.mark.parametrize('data',[b'{}',b'{"count":null}',b'{"count":true}',b'{"count":-1}',b'not json'])
def test_invalid_tokenization_is_not_a_zero_token_success(data):
    calls=[]
    def opener(request,**kwargs):
        calls.append(request.full_url);return io.BytesIO(data)
    gateway=OpenAICompatibleGateway('http://127.0.0.1:8000','test-key','test-model',opener=opener,max_context_tokens=49152)
    with pytest.raises(JudgmentServiceError) as error:gateway('system','user')
    assert error.value.detail['kind']=='tokenization_failed'
    assert calls==['http://127.0.0.1:8000/tokenize']
    assert gateway.last_request_body is None
