"""Agreed response structure and exact current-document item lookup only."""
from copy import deepcopy
import re
import unicodedata
from pathlib import Path

PROMPT = Path(__file__).with_name('fast_judgment_prompt.txt').read_text(encoding='utf-8')
VERDICTS = {'BENIGN', 'LIKELY_BENIGN', 'LIKELY_MALICIOUS', 'MALICIOUS', 'UNKNOWN'}

# Only these declared fields belong to the service response. Provider output is
# retained separately; extra fields cannot enter public or deep-analysis input.
# None marks an unmodified leaf, and a one-item tuple marks an array of objects.
_RESPONSE_FIELDS = {
    'verdict': None, 'summary': None,
    'reasons': ({'text': None, 'related_items': ({
        'section_title': None, 'item_label': None},)},),
    'decision_notes': {
        'provisional_assessment': {
            'direction_basis': None,
            'consequential_uncertainty': None},
        'unknown': {
            'blocking_gap': None,
            'why_available_facts_do_not_support_other_verdicts': None,
            'information_that_would_enable_assessment': None},
        'follow_up_questions': ({
            'question': None, 'why_it_could_change_the_decision': None},)},
}


def _declared_fields(value, fields):
    """Select fields without filling missing keys, moving values or coercion."""
    if isinstance(fields, dict) and isinstance(value, dict):
        return {key: _declared_fields(item, fields[key])
                for key, item in value.items() if key in fields}
    if isinstance(fields, tuple) and isinstance(value, list):
        return [_declared_fields(item, fields[0]) for item in value]
    # Wrong types and unexpected non-null conditional objects remain visible to
    # the existing validator. Nothing here repairs their required contents.
    return value


def _object(value, keys, name):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError('invalid_' + name)


def _text(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError('nonempty_text_required')


def validate_response(value):
    """Structure, types and conditional presence; no semantic citation judge."""
    value = _declared_fields(value, _RESPONSE_FIELDS)
    _object(value, ('verdict', 'summary', 'reasons', 'decision_notes'), 'response')
    if not isinstance(value['verdict'], str) or value['verdict'] not in VERDICTS:
        raise ValueError('invalid_verdict')
    _text(value['summary'])
    reasons = value['reasons']
    if not isinstance(reasons, list) or (not reasons and value['verdict'] != 'UNKNOWN'):
        raise ValueError('invalid_reasons')
    for reason in reasons:
        _object(reason, ('text', 'related_items'), 'reason')
        _text(reason['text'])
        if not isinstance(reason['related_items'], list):
            raise ValueError('invalid_related_items')
        for reference in reason['related_items']:
            _object(reference, ('section_title', 'item_label'), 'related_item')
            _text(reference['section_title']); _text(reference['item_label'])
    notes = value['decision_notes']
    _object(notes, ('provisional_assessment', 'unknown', 'follow_up_questions'), 'decision_notes')
    if value['verdict'] in ('LIKELY_BENIGN', 'LIKELY_MALICIOUS'):
        provisional = notes['provisional_assessment']
        _object(provisional, ('direction_basis', 'consequential_uncertainty'), 'provisional_assessment')
        for text in provisional.values():
            _text(text)
    elif notes['provisional_assessment'] is not None:
        raise ValueError('unexpected_provisional_assessment')
    if value['verdict'] == 'UNKNOWN':
        unknown = notes['unknown']
        _object(unknown, ('blocking_gap', 'why_available_facts_do_not_support_other_verdicts',
                          'information_that_would_enable_assessment'), 'unknown')
        for text in unknown.values():
            _text(text)
    elif notes['unknown'] is not None:
        raise ValueError('unexpected_unknown')
    if not isinstance(notes['follow_up_questions'], list):
        raise ValueError('invalid_follow_up_questions')
    for question in notes['follow_up_questions']:
        _object(question, ('question', 'why_it_could_change_the_decision'), 'question')
        for text in question.values():
            _text(text)
    return deepcopy(value)


def _link_name(value):
    value = unicodedata.normalize('NFKC', value).casefold()
    return re.sub(r'\s+', '', value.translate(str.maketrans({'—': '-', '–': '-', '−': '-'})))


def _one_korean_edit(left, right):
    # Only a Korean spelling edit is tolerated. Keep numbers, hosts and paths exact.
    if re.sub(r'[가-힣]', '', left) != re.sub(r'[가-힣]', '', right):
        return False
    if abs(len(left) - len(right)) > 1:
        return False
    if len(left) == len(right):
        return sum(a != b for a, b in zip(left, right)) == 1
    short, long = (left, right) if len(left) < len(right) else (right, left)
    for i in range(len(long)):
        if short == long[:i] + long[i + 1:]:
            return True
    return False


def _link_candidates(selected, index, rows):
    pair = (selected['section_title'], selected['item_label'])
    if pair in index:
        return index[pair], 'exact'
    section, item = map(_link_name, pair)
    normalized = [r for r in rows if _link_name(r['section_title']) == section
                  and _link_name(r['item_label']) == item]
    if normalized:
        return normalized, 'normalized'
    # A real item copied into the section field still identifies a link only
    # when that item exists once across the complete approved catalogue.
    unique_item = [r for r in rows if _link_name(r['item_label']) == item]
    if unique_item:
        return unique_item, 'item_label'
    nearby = [r for r in rows if _link_name(r['section_title']) == section
              and _one_korean_edit(item, _link_name(r['item_label']))]
    return nearby, 'korean_spelling'


def link_judgment(value, context):
    value = validate_response(value)
    index = {}
    for row in context['item_mapping']:
        index.setdefault((row['section_title'], row['item_label']), []).append(row)
    reasons, diagnostics = [], []
    for i, reason in enumerate(value['reasons'], 1):
        fact_ids = []
        for selected in reason['related_items']:
            matches, method = _link_candidates(selected, index, context['item_mapping'])
            state = ('unresolved' if not matches else 'ambiguous' if len(matches) > 1
                     else 'resolved' if matches[0]['fact_ids'] else 'model_only')
            if state == 'resolved':
                fact_ids.extend(matches[0]['fact_ids'])
            diagnostics.append({'reason_id': f'r{i}', **selected, 'status': state,
                                'match_method': method})
        reasons.append({'reason_id': f'r{i}', 'text': reason['text'],
                        'related_fact_ids': list(dict.fromkeys(fact_ids))})
    return {'verdict': value['verdict'], 'summary': value['summary'], 'reasons': reasons}, diagnostics
