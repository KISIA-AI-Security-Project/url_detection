"""Public-link resolution tolerates names without changing model meaning."""
from copy import deepcopy
from evidence_pipeline.fast_judgment import link_judgment


def response(section, item):
    return {'verdict': 'MALICIOUS', 'summary': '저장된 모델 설명.',
            'reasons': [{'text': '저장된 이유.', 'related_items': [
                {'section_title': section, 'item_label': item}]}],
            'decision_notes': {'provisional_assessment': None, 'unknown': None, 'follow_up_questions': []}}


def row(section, item, fid):
    return {'section_title': section, 'item_label': item, 'fact_ids': [fid] if fid else []}


def test_unique_real_item_resolves_when_model_copies_item_into_section():
    value = response('인증서 — rust-lang.org', '인증서 — rust-lang.org')
    before = deepcopy(value)
    linked, diagnostics = link_judgment(value, {'item_mapping': [
        row('L2 TLS 접속과 인증서', '인증서 — rust-lang.org', 's4-f1')]})
    assert linked['reasons'][0]['related_fact_ids'] == ['s4-f1']
    assert diagnostics[0]['match_method'] == 'item_label'
    assert linked['summary'] == value['summary'] and linked['verdict'] == value['verdict']
    assert value == before


def test_spacing_dash_and_single_korean_spelling_are_only_name_tolerance():
    context = {'item_mapping': [row('페이지에 선언된 내용', '정적 본문 인용', 's1-f1')]}
    for section, item in [('페이지에 선언된 내용', '정적 본믄 인용'),
                          ('페이지에선언된내용', '정적본문인용')]:
        linked, diagnostics = link_judgment(response(section, item), context)
        assert linked['reasons'][0]['related_fact_ids'] == ['s1-f1']
        assert diagnostics[0]['status'] == 'resolved'


def test_duplicate_items_and_spelling_candidates_stay_ambiguous():
    context = {'item_mapping': [row('A', '입력 1', 's1-f1'), row('B', '입력 1', 's2-f1')]}
    linked, diagnostics = link_judgment(response('없는 구획', '입력 1'), context)
    assert linked['reasons'][0]['related_fact_ids'] == []
    assert diagnostics[0]['status'] == 'ambiguous'


def test_numbers_hosts_paths_and_absent_items_are_not_guessed():
    context = {'item_mapping': [row('구획', '입력 1', 's1-f1'),
                                row('구획', '인증서 — site.com', 's1-f2')]}
    for item in ('입력 2', '인증서 — site.co', '만들어진 항목'):
        linked, diagnostics = link_judgment(response('구획', item), context)
        assert linked['reasons'][0]['related_fact_ids'] == []
        assert diagnostics[0]['status'] == 'unresolved'


def test_model_only_item_never_becomes_public_fact():
    linked, diagnostics = link_judgment(response('틀린 구획', '자료 범위'), {
        'item_mapping': [row('관측 범위', '자료 범위', None)]})
    assert linked['reasons'][0]['related_fact_ids'] == []
    assert diagnostics[0]['status'] == 'model_only'
