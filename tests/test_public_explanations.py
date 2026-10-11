"""Public metadata must preserve conditions and remain a compatible contract."""
from copy import deepcopy
import pytest

from evidence_pipeline.fast_public import make_public_result, validate_public_result
from evidence_pipeline.public_explanations import certificate, http_detail, url_subject, shared_metadata, html_control
from evidence_pipeline.fast_context import build_fast_context
from test_fast_result_contract import recorded_case


def test_plain_contract_legacy_and_invalid_metadata():
    _, _, records, raws, refs, native, _, _ = recorded_case('login')
    context = build_fast_context(records, raws, native=native, artifact_refs=refs)
    public = make_public_result(context['job_id'], context['attempt'], context=context)
    assert all(f.get('plain') for f in public['details']['facts'])
    legacy = deepcopy(context)
    for fact in legacy['details']['facts']:
        fact.pop('plain', None)
    make_public_result(legacy['job_id'], legacy['attempt'], context=legacy)
    for wrong in [None, '', {'title': '제목', 'text': ''}, {'title': 1, 'text': '설명'}, {'title': '제목', 'text': '설명', 'raw': {}}]:
        value = deepcopy(public); value['details']['facts'][0]['plain'] = wrong
        with pytest.raises(ValueError):
            validate_public_result(value, job_id=public['job_id'], attempt=public['attempt'])


def test_url_parsing_and_file_name_do_not_claim_execution():
    assert '실제로 접속' not in url_subject({'접속 호스트': 'example.com'})['title']
    result = http_detail('http_file_type_match', {'목록에 해당한 확장자': 'exe'})
    assert '파일 이름에 적힌 확장자' in result['text']
    assert '본문 앞부분에서 추정한' not in result['text']
    assert '실제 파일 실행을 확인한 결과는 아닙니다' in result['text']


def test_certificate_name_fallback_does_not_claim_browser_acceptance():
    result = certificate({'inspected_host': 'example.com', 'TLS 접속 호스트와 인증서 이름 대조': '일치 (SAN 없이 CN으로 보완 대조)'})
    assert '보완 대조' in result['text']
    assert '브라우저가 인증서를 받아들인다는 뜻은 아닙니다' in result['text']
    result = certificate({'inspected_host': 'example.com', 'TLS 접속 호스트와 인증서 이름 대조': '일치 (SAN 기준)', '서버 인증서 검증': '실패'}, [('certificate_validity', {'인증서 유효기간 상태': '검사 당시 만료됨'})])
    assert '검증에 실패' in result['text'] and '만료된 상태' in result['text']


def test_real_page_image_settings_and_unassociated_buttons_keep_their_scope():
    for key, value in [('og:image:height', '546'), ('og:image:type', 'image/png'), ('og:image:width', '1200')]:
        result = shared_metadata(key, value)
        assert '문구' not in result['title'] and '다음 문구' not in result['text']
        assert value in result['text'] and '설정' in result['text']
    unassociated = html_control({'type': 'submit', 'form_id': None, 'text': 'Menu'})
    assert '연결된 입력 폼은 기록되지 않았습니다' in unassociated['text']
    assert '제출 기능을 가진' not in unassociated['text']
