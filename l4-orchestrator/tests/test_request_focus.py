"""Optional user focus survives reception, stored handoff and first SDK input."""
import asyncio
import json
from pathlib import Path
import sys

import pytest

WORKSPACE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(WORKSPACE / 'evaluation/remediation-20260911/repo'))
from evidence_pipeline.request_options import normalize_request_text
from l4_orchestrator.aws_query import HttpError
from l4_orchestrator.aws_start import parse_input, request_key, run_identity
from l4_orchestrator.sdk_runtime import run_l4
from l4_orchestrator.sdk_types import ExecutionLimits
from test_aws_start import INPUT, Ledger, ActualFastObjects, Dispatcher, event, invoke
from test_sdk_runtime import RUN_CONFIG, ScriptModel, setup, turn


@pytest.mark.parametrize('value', [None, 1, [], {}, 'x' * 2001, '\ud800'])
def test_invalid_request_focus_is_rejected_before_dispatch(value):
    incoming = event()
    incoming['body'] = json.dumps(INPUT | {'request_text': value})
    dispatch = Dispatcher()
    with pytest.raises(HttpError):
        invoke(Ledger(), ActualFastObjects(), dispatch, incoming)
    assert not dispatch.calls


def test_blank_focus_keeps_legacy_identity_and_unicode_budget_is_explicit():
    incoming = event()
    incoming['body'] = json.dumps(INPUT | {'request_text': ' \n\t '})
    assert parse_input(incoming) == INPUT
    assert run_identity(parse_input(incoming)) == run_identity(INPUT)
    assert normalize_request_text('😀' * 2000) == '😀' * 2000


def test_same_focus_reuses_run_different_focus_dispatches_separately():
    ledger, objects, dispatch = Ledger(), ActualFastObjects(), Dispatcher()
    incoming = event()
    incoming['body'] = json.dumps(INPUT | {'request_text': '  로그인 버튼의 이동 경로를 확인해 주세요.\n '})
    first = invoke(ledger, objects, dispatch, incoming)
    again = invoke(ledger, objects, dispatch, incoming)
    incoming['body'] = json.dumps(INPUT | {'request_text': '첨부 파일의 형식을 확인해 주세요.'})
    second = invoke(ledger, objects, dispatch, incoming)
    assert first['run_id'] == again['run_id'] != second['run_id']
    assert len(dispatch.calls) == 2
    saved = json.loads(objects.requests[request_key(first['run_id'])])
    assert saved['input']['request_text'] == '로그인 버튼의 이동 경로를 확인해 주세요.'


@pytest.mark.parametrize('manager_calls', [1, 3])
def test_focus_reaches_first_manager_as_user_input_exactly_once(manager_calls):
    async def check():
        builder = {'builder_context': '기존 정적 관측과 한계'}
        judgment = {'verdict': 'UNKNOWN'}
        focus = '로그인 버튼을 누르면 어디로 이동하는지 확인해 주세요.\n실제 전송 대상도 궁금합니다.'
        final = {'summary': '오프라인 입력 전달 확인', 'findings': [], 'limits': []}
        store, registry, io, publisher = setup()
        manager = ScriptModel(turn(finish=final))
        await run_l4(job_id=store.job_id, initial_findings=builder, previous_judgment=judgment,
                     request_text=focus, store=store, publisher=publisher, registry=registry,
                     model_name=manager, executor_model=ScriptModel(),
                     execution_limits=ExecutionLimits(None, manager_calls, 2, None, None), run_config=RUN_CONFIG)
        messages = manager.calls[0]['input']
        first = next(m for m in messages if m.get('role') == 'user')
        content = first['content']
        data = json.loads(content if isinstance(content, str) else content[0]['text'])
        assert data['request_text'] == focus
        assert data['initial_findings'] == builder and data['previous_judgment'] == judgment
        assert sum('request_text' in str(m.get('content')) for m in messages) == 1
        assert focus not in str(manager.calls[0].get('instructions', ''))
    asyncio.run(check())


def test_saved_fast_adapter_preserves_optional_focus_and_original_builder(tmp_path):
    from l4_orchestrator.aws_runner import prepare_fast_input
    from l4_orchestrator.tools.record_reader import RecordReader
    from test_aws_start import FAST
    class SavedStore:
        def get_bytes(self, key, optional=False):
            return (FAST / key).read_bytes()
        def get(self, key, optional=False):
            return json.loads(self.get_bytes(key))
    focus = '페이지의 입력값이 전송되는 주소를 확인해 주세요.'
    prepared = prepare_fast_input(INPUT | {'request_text': focus}, SavedStore(), tmp_path,
                                  RecordReader({}, max_data_bytes=524288))
    assert prepared['request_text'] == focus
    assert 'request_text' not in prepared['initial_findings']
    context = SavedStore().get(f"records/{INPUT['job_id']}/{INPUT['attempt']}/fast/context.json")
    assert prepared['initial_findings']['builder_context'] == context['model_body']
