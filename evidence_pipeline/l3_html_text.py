"""Source-bound HTML decision context; no parsing, policy calls or URL verdicts.

HTML facts are selected from the same raw/record pair, rather than the legacy
document inventory (which already shortens text). Full inputs and every omission
remain in the external audit. JavaScript has an explicit, separate review scope.
"""
from copy import deepcopy
from dataclasses import asdict
import re

from .records import canonical, digest
from .record_contract import validate_record
from .text_blocks import TextBlock, field

VERSION = 'l3-html-text-2'
HTML_IDS = tuple(f'L3-H-{i:02d}' for i in range(1, 9))
DEFAULT_TEXT_CHARS = 6000
DEFAULT_MAX_BYTES = 200_000
BRAND_SOURCE_LABELS = {
    'title': '문서 제목',
    'og_site_name': 'HTML의 사이트 이름(og:site_name)',
    'hostname': '문서 주소의 호스트 이름',
}

LIMITS = {
    'brand_not_identified': '정책이 브랜드를 식별하지 못함',
    'brand_identifier_not_configured': '브랜드 식별 정책이 설정되지 않음',
    'brand_domain_reference_not_configured': '브랜드 참조 도메인 자료가 설정되지 않음',
    'brand_absent_from_domain_reference': '식별한 브랜드가 참조 도메인 자료에 없음',
    'brand_comparison_domain_unresolved': '현재 문서의 비교 도메인이 미확정',
    'brand_domain_reference_empty': '해당 브랜드의 참조 도메인 목록이 비어 있음',
    'brand_domain_reference_invalid': '해당 브랜드의 참조 도메인을 해석하지 못함',
    'brand_resource_evaluator_not_configured': '리소스 대조 정책이 설정되지 않음',
    'brand_resource_evaluator_invalid': '설정된 리소스 대조 정책을 실행할 수 없음',
    'brand_resource_evaluator_abstained': '리소스 대조 정책이 판단을 보류함',
    'brand_resource_evaluator_invalid_result': '리소스 대조 정책이 유효한 결과를 반환하지 않음',
    'credential_classification_failed': '이 입력의 자격정보 분류에 실패함',
    'credential_classification_partial': '일부 입력의 자격정보 분류가 미확정',
    'html_source_truncated': '일부 HTML만 확보되어 추가 구조와 선언은 미확인',
    'html_analysis_incomplete': '일부 HTML만 분석하여 전체 문서의 부재를 확정할 수 없음',
    'html_not_parsed': 'HTML 구조를 파싱하지 못함',
    'html_source_unavailable': 'HTML 원문을 확보하지 못함',
    'inline_handlers_unanalyzed': '입력·요소에 선언된 이벤트 코드의 연결과 효과는 HTML 단계에서 미해석',
}
NATIVE = {
    'excluded_disabled': '기록된 disabled 상태에서 기본 폼 제출 항목으로 제외됨',
    'excluded_non_submit_control': 'button/reset 항목은 기본 폼 제출 값 항목에서 제외됨',
    'coordinates_only_if_activated_submitter': '활성화한 image 제출 컨트롤의 좌표 항목 조건이 있음',
    'unknown_name_not_recorded': '이름 속성이 미기록되어 기본 제출의 이름 조건은 미확정',
    'excluded_missing_name': '비어 있거나 없는 이름 때문에 기본 폼 제출 값 항목에서 제외됨',
    'unknown_disabled_state_not_recorded': 'disabled 상태가 미기록되어 기본 제출 참여는 미확정',
    'excluded_unchecked': '기록된 미선택 상태에서 기본 폼 제출 항목으로 제외됨',
    'conditional_checked_state_required': '기본 제출 참여에는 선택 상태가 필요하며 그 상태는 미확정',
    'conditional_activated_submitter_required': '기본 제출 참여에는 이 제출 컨트롤의 활성화가 필요함',
}


def validate_input_bundle(records, raws):
    """Validate the whole bundle before selecting an explicitly narrower view."""
    if not records or len({r['layer'] for r in records}) != len(records):
        raise ValueError('html_context_missing_or_duplicate_layer')
    if len({(r['request_id'], str(r['attempt'])) for r in records}) != 1:
        raise ValueError('html_context_mixed_request_or_attempt')
    if set(raws) != {r['layer'] for r in records}:
        raise ValueError('html_context_raw_record_layers_differ')
    for record in records:
        if record.get('record_contract_version'):
            validate_record(record)
        if digest(raws[record['layer']]) != record['raw_ref']['sha256']:
            raise ValueError('html_context_raw_record_hash_mismatch')


def assemble(blocks):
    body, mapping = '', []
    for block in blocks:
        if not block.lines:
            raise ValueError('empty_html_text_block')
        if body:
            body += '\n\n'
        start = len(body)
        body += '[' + block.title + ']\n' + '\n'.join(block.lines)
        mapping.append({'title': block.title, 'start': start, 'end': len(body),
                        'source_evidence_ids': list(block.evidence_ids)})
    return body + '\n', mapping


def validate_target_input(record, raw, native):
    """Compare only supplied values in the same role; redirects keep both roles."""
    targets = [record.get('target') or {}]
    if native is not None:
        targets.append(native.get('target') or {})
    snapshots = [s for s in (raw.get('shared_page'),
                 (record.get('coverage') or {}).get('shared_page_observation'),
                 (native or {}).get('shared_page_observation')) if isinstance(s, dict)]
    original = [t.get('original_url') for t in targets] + [s.get('original_url') for s in snapshots]
    document = [t.get('document_url') for t in targets] + [(raw.get('html') or {}).get('document', {}).get('url')]
    document += [s.get('final_url') or s.get('current_url') for s in snapshots]
    domain = [t.get('etld1') for t in targets] + [(raw.get('html') or {}).get('document', {}).get('etld1')]
    for role, values in [('original', original), ('document', document), ('icann_domain', domain)]:
        known = [v for v in values if v is not None]
        if known and any(canonical(v) != canonical(known[0]) for v in known[1:]):
            raise ValueError('html_' + role + '_subject_mismatch')
    for key in ('snapshot_id', 'captured_body_sha256'):
        known = [s[key] for s in snapshots if s.get(key) is not None]
        if known and any(v != known[0] for v in known[1:]):
            raise ValueError('html_snapshot_binding_mismatch')


def validate_native_input(record, raw, native):
    validate_target_input(record, raw, native)
    if native is None:
        return
    if native.get('raw') is not None and canonical(native['raw']) != canonical(raw):
        raise ValueError('html_native_raw_mismatch')
    native_signals = {s['id']: s for s in native.get('signals', [])}
    if set(native_signals) != {s['id'] for s in record.get('signals', [])}:
        raise ValueError('html_native_record_signal_mismatch')
    for signal in record.get('signals', []):
        other = native_signals[signal['id']]
        if any(canonical(signal.get(k)) != canonical(other.get(k)) for k in ('detected', 'evidence')):
            raise ValueError('html_native_record_signal_mismatch')
    facts = [{k: v for k, v in f.items() if k not in {'raw_reference', 'record_reference'}}
             for f in record.get('analysis_facts', [])]
    if canonical(facts) != canonical(native.get('analysis_facts', [])):
        raise ValueError('html_native_record_analysis_fact_mismatch')


from .presentation_items import PresentationCapture
from .public_explanations import (plain, declared_text, form_declaration, html_field,
                                 html_link, html_frame, html_refresh, html_control,
                                 shared_metadata)


class _HTML(PresentationCapture):
    def __init__(self, record, raw, text_chars):
        self.record, self.raw = record, raw
        self.html = raw.get('html') or {}
        self.doc = self.html.get('document') or {}
        self.signals = {s['id']: (i, s) for i, s in enumerate(record.get('signals', []))
                        if s['id'] in HTML_IDS}
        if len(self.signals) != len([s for s in record.get('signals', []) if s['id'] in HTML_IDS]):
            raise ValueError('duplicate_html_signal')
        target = record.get('target', {}).get('document_url')
        if target is not None and self.doc.get('url') is not None and target != self.doc['url']:
            raise ValueError('html_document_subject_mismatch')
        for key, raw_key in [('html_parsed', 'parse_succeeded'), ('html_source_complete', 'source_complete')]:
            value = record.get('coverage', {}).get(key)
            if value is not None and self.doc.get(raw_key) is not None and value != self.doc[raw_key]:
                raise ValueError('html_observation_scope_mismatch:' + key)
        self.causes = {c['id']: (i, c) for i, c in enumerate(record.get('causes', []))}
        self.blocks, self.line_map, self.omissions = [], [], []
        self.text_chars, self.used_causes = text_chars, set()
        self.lines, self.ids = [], []
        self.control_count = 0

    def start(self, title):
        self.title, self.lines, self.ids = title, [], []
        self.reset_items()

    def add(self, label, value, *sources, ids=(), indent='', public=True):
        # Labels can include supplied OG property names; quote a multiline name
        # separately so it cannot become a new generated heading.
        if '\n' in label or '\r' in label:
            self.add('항목 이름(기록된 선언)', label, *sources, ids=ids, indent=indent, public=public)
            label = '선언 값'
        for line in field(label, value):
            rendered = indent + re.sub(r'\r\n|\r|\n', lambda m: m.group() + indent, line)
            self.lines.append(rendered)
            self.line_map.append({'title': self.title, 'line_in_block': len(self.lines),
                                  'text': rendered, 'sources': list(sources)})
            self.capture([rendered], sources, ids, public=public and value is not None)
        self.ids.extend(ids)

    def note(self, text, *sources, ids=(), indent='', public=False):
        rendered = indent + re.sub(r'\r\n|\r|\n', lambda m: m.group() + indent + '  ', text)
        self.lines.append(rendered)
        self.line_map.append({'title': self.title, 'line_in_block': len(self.lines),
                              'text': rendered, 'sources': list(sources)})
        self.ids.extend(ids)
        self.capture([rendered], sources, ids, public=public)

    def finish(self):
        if self.lines:
            self.blocks.append(TextBlock(self.title, self.lines, tuple(dict.fromkeys(self.ids)),
                                         [v for v in self.items if v['lines']]))

    def rp(self, sid, path='/evidence'):
        return {'source': 'record', 'pointer': f'/signals/{self.signals[sid][0]}' + path}

    @staticmethod
    def hp(path):
        return {'source': 'raw', 'pointer': '/html' + path}

    @staticmethod
    def og(key):
        return _HTML.hp('/open_graph/' + key.replace('~', '~0').replace('/', '~1'))

    def evidence(self, sid):
        return self.signals.get(sid, (None, {}))[1].get('evidence') or {}

    def omit(self, pointer, reason, source='raw'):
        self.omissions.append({'source': source, 'pointer': pointer, 'reason': reason})

    def cause(self, cause_id, label, indent=''):
        if cause_id in self.used_causes:
            return
        self.used_causes.add(cause_id)
        index, cause = self.causes[cause_id]
        detail = cause.get('detail') or {}
        code = cause.get('code')
        text = LIMITS.get(code, detail.get('message') or detail.get('error') or str(code or '이유 미기록'))
        pointer = {'source': 'record', 'pointer': f'/causes/{index}'}
        self.add(label, text, pointer, ids=(cause_id,), indent=indent, public=False)
        if code in LIMITS and detail.get('message') and code in {'credential_classification_failed'}:
            self.add('기록된 이유', detail['message'], pointer, indent=indent, public=False)
        for key, name in [('brand', '대상 브랜드'), ('document_url', '대상 문서')]:
            if detail.get(key) and detail[key] != self.doc.get('url'):
                self.add(name, detail[key], pointer, indent=indent, public=False)

    def signal_limits(self, sid, label, indent=''):
        signal = self.signals.get(sid, (None, {}))[1]
        for cid in signal.get('cause_ids', []):
            if cid not in self.causes:
                raise ValueError('dangling_html_cause')
            # Field failures and common source limits are shown at their subject.
            code = self.causes[cid][1].get('code')
            if code in {'credential_classification_failed', 'credential_classification_partial',
                        'html_source_truncated', 'html_analysis_incomplete', 'html_not_parsed'}:
                continue
            if self.doc.get('parse_succeeded') is False and code in {'html_parse_error', 'invalid_html_type', 'missing_html'}:
                continue  # Source failures belong to the HTML subject/limits, not brand policy.
            self.cause(cid, label, indent)
        if signal and signal.get('detected') is None and not signal.get('cause_ids') and sid in {'L3-H-05', 'L3-H-06'}:
            self.note(label + ': 정책 대조 결과는 미확정이며 세부 이유는 미기록.',
                      self.rp(sid, '/detected'), ids=(sid,), indent=indent)

    def subject(self):
        self.start('HTML 관측 대상과 주소 해석')
        url = self.doc.get('url') or self.record.get('target', {}).get('document_url')
        if url:
            self.add('문서', url, self.hp('/document/url'))
        original = self.record.get('target', {}).get('original_url')
        if original and original != url:
            self.add('최초 요청 URL', original, {'source': 'record', 'pointer': '/target/original_url'})
        available, complete, parsed = (self.doc.get(k) for k in ('source_available', 'source_complete', 'parse_succeeded'))
        if available is False:
            scope = 'HTML 원문을 확보하지 못함. 빈 문서를 관측한 결과가 아님.'
        elif parsed is False:
            scope = 'HTML 원문은 확보됐으나 구조를 파싱하지 못함.' if available is True else 'HTML 파싱 결과 없음; 원문 확보 여부는 미기록.'
        elif complete is False:
            scope = '일부 HTML을 파싱함. 기록된 구조는 유지하지만 추가 구조와 선언의 부재는 미확인.'
        elif parsed is True and complete is True:
            scope = '기록상 잘림 없는 HTML을 파싱함.'
        else:
            scope = '정적 HTML 관측; 원문 전체 확보 또는 파싱 범위의 일부는 미기록.'
        if available is True and parsed is True and self.html.get('source') == '':
            scope = '확보한 빈 HTML을 파싱함.'
        shared = [(cid, i) for cid, (i, c) in self.causes.items()
                  if ((complete is False and c.get('code') in {'html_source_truncated', 'html_analysis_incomplete'})
                      or (available is False and c.get('code') == 'missing_html')
                      or (parsed is False and c.get('code') == 'html_not_parsed'))]
        self.used_causes.update(cid for cid, _ in shared)
        self.note('원문 범위: ' + scope, self.hp('/document'),
                  *({'source': 'record', 'pointer': f'/causes/{i}'} for _, i in shared), ids=tuple(cid for cid, _ in shared))
        self.note('이번 본문 범위: HTML의 정적 선언과 제공된 정책·구조 결과. JavaScript 분석 결과는 포함하지 않음.',
                  {'source': 'selection', 'pointer': '/scope'})
        self.note('페이지 코드의 브라우저 실행·사용자 입력값·실제 제출과 이동은 미관측.',
                  {'source': 'record', 'pointer': '/coverage/browser_execution_observed'})
        base = self.html.get('base')
        effective = self.doc.get('effective_base_url')
        if base:
            if base.get('valid') is True:
                if effective:
                    self.add('base로 기록된 상대 주소 기준', effective, self.hp('/document/effective_base_url'), ids=('L3-H-08',))
                else:
                    self.note('base 선언은 유효하나 실제 해석 기준은 미기록.', self.hp('/base'), ids=('L3-H-08',))
            else:
                self.add('해석하지 못한 base 선언', base.get('raw_href'), self.hp('/base/raw_href'), ids=('L3-H-08',))
                self.add('기록된 상대 주소 기준', effective, self.hp('/document/effective_base_url'))
            self.note('base는 주소 해석 기준 선언이며 페이지 이동 결과가 아님.', self.hp('/base'))
        elif effective == url and url:
            self.note('상대 주소 기준: 문서 주소.', self.hp('/document/effective_base_url'), ids=('L3-H-08',))
        elif effective:
            self.add('기록된 상대 주소 기준', effective, self.hp('/document/effective_base_url'))
        elif parsed is True:
            self.note('상대 주소 해석 기준은 미기록.', self.hp('/document'))
        if parsed is True:
            self.note('구조화 범위: base·meta refresh·favicon은 첫 항목, 같은 Open Graph 속성은 마지막 값으로 제공됨. 반복 선언 전체를 각각 분석한 결과는 아님.',
                      {'source': 'selection', 'pointer': '/producer_scope'})
        self.finish()

    def quote(self, label, text, pointer):
        if len(text) <= self.text_chars:
            self.add(label, text, pointer)
            return
        head = self.text_chars * 2 // 3
        tail = self.text_chars - head
        self.add(label + ' (앞부분 인용)', text[:head], pointer)
        self.add(label + ' (뒷부분 인용)', text[-tail:], pointer)
        self.note('인용 범위: 중간 부분은 이 본문에서 생략했으며 전체 원문은 내부 자료에 보존됨.', pointer)
        self.omissions.append({'source': 'raw', 'pointer': pointer['pointer'],
                               'reason': 'bounded source-order head/tail quotation, no semantic ranking',
                               'omitted_range': [head, len(text) - tail],
                               'included_ranges': [[0, head], [len(text) - tail, len(text)]]})

    def page(self):
        self.start('페이지에 선언된 내용')
        seen = {}
        seen_plain = {}
        title = self.doc.get('title')
        if title:
            self.begin_item('제목', plain=declared_text('페이지에 적힌 제목', title))
            self.add('제목', title, self.hp('/document/title'))
            seen[title] = '제목'
            seen_plain[title] = '페이지에 적힌 제목'
        text = self.doc.get('visible_text')
        if text:
            self.begin_item('정적 본문 인용', plain=declared_text('HTML에서 읽은 페이지 문구', text))
            self.quote('정적 본문 인용', text, self.hp('/document/visible_text'))
            scope = self.doc.get('text_scope')
            if scope == 'static HTML text excluding explicit hidden nodes; external CSS and runtime visibility unobserved':
                self.note('본문은 명시적 숨김 요소와 head·script·style·template·noscript를 제외한 정적 텍스트. 외부 CSS와 실행 후 실제 표시 상태는 미관측.', self.hp('/document/text_scope'))
            else:
                self.add('기록된 본문 추출 범위', scope, self.hp('/document/text_scope'), public=False)
            seen[text] = '정적 본문 인용'
            seen_plain[text] = 'HTML에서 읽은 페이지 문구'
        for key, value in (self.html.get('open_graph') or {}).items():
            if value.get('resource_url'):
                continue  # Declared URL is shown once with its resource roles.
            literal = value.get('raw_content')
            if literal is not None and literal != '':
                metadata_plain = shared_metadata(key, literal, seen_plain.get(literal))
                self.begin_item('공유 메타데이터 ' + key,
                                plain=metadata_plain)
                if literal in seen:
                    self.note('공유 메타데이터 ' + key + ': ' + seen[literal] + '과 같은 값으로 선언됨.', self.og(key), public=True)
                    self.omit(self.og(key)['pointer'], 'same declared value; role and equality retained without repeating value')
                else:
                    self.add('공유 메타데이터 ' + key, literal, self.og(key))
                    seen[literal] = '공유 메타데이터 ' + key
                    seen_plain[literal] = metadata_plain['title']
        self.finish()

    def relations(self, value, *pointers, indent=''):
        relation = value.get('relations') or {}
        match = value.get('domain_match')
        current, target = value.get('current_etld1'), value.get('action_etld1')
        if type(match) is bool:
            if current is None or target is None or (current == target) != match:
                raise ValueError('html_domain_comparison_not_established')
        if relation.get('same_origin') is True:
            text = '문서와 프로토콜·호스트·포트가 같음.'
        elif relation.get('same_host') is True:
            text = '문서와 호스트가 같음.'
            if relation.get('same_origin') is False:
                text += ' 프로토콜 또는 포트가 달라 같은 오리진은 아님.'
        elif relation.get('same_icann_domain') is True or match is True:
            text = '문서와 ICANN 등록 도메인이 같음.'
            if relation.get('same_host') is False:
                text += ' 호스트는 다름.'
        elif relation.get('same_icann_domain') is False or match is False:
            text = '문서와 ICANN 등록 도메인이 다름.'
        else:
            text = '문서와의 주소 관계는 비교 불가 또는 미기록.'
        comparable = any(type(v) is bool for v in relation.values()) or type(match) is bool
        self.note('주소 관계: ' + text, *pointers, indent=indent, public=comparable)
        # This is a different comparison axis; ICANN equality cannot erase it.
        if relation.get('same_site_scope') is False:
            self.note('사이트 범위: 문서와 다름(공유 호스팅의 private suffix를 포함한 기록 기준).', *pointers, indent=indent, public=True)
        elif relation.get('same_site_scope') is None and relation:
            self.note('사이트 범위 대조: 미확정.', *pointers, indent=indent)

    def forms(self):
        forms, inputs, buttons = (self.html.get(k) or [] for k in ('forms', 'inputs', 'buttons'))
        classification = self.html.get('credential_classification') or {}
        observations = self.evidence('L3-H-02').get('field_observations', classification.get('fields', []))
        classes = {o['field_id']: o for o in observations if o.get('field_id')}
        for entry in classification.get('fields', []):
            if entry.get('field_id') in classes and classes[entry['field_id']] != entry:
                raise ValueError('html_field_classification_mismatch')
        for known in self.evidence('L3-H-02').get('fields', []):
            item = classes.get(known.get('field_id'))
            if item is None:
                classes[known['field_id']] = {**known, 'state': 'evaluated'}
            elif any(item.get(k) != known.get(k) for k in ('form_id', 'credential_type')):
                raise ValueError('html_classified_field_record_mismatch')
        by_id = {f.get('form_id'): (i, f) for i, f in enumerate(forms)}
        field_ids = {f.get('field_id') for f in inputs}
        if len(field_ids) != len(inputs) or len(by_id) != len(forms):
            raise ValueError('duplicate_html_form_or_field_identity')
        for fid, item in classes.items():
            matches = [f for f in inputs if f.get('field_id') == fid]
            if len(matches) != 1 or matches[0].get('form_id') != item.get('form_id'):
                raise ValueError('html_field_form_source_mismatch')
        for form_id in self.evidence('L3-H-01').get('form_ids', []):
            if form_id not in by_id or not any(o.get('form_id') == form_id and o.get('credential_type') for o in classes.values()):
                raise ValueError('html_credential_form_record_mismatch')
        h3 = {x.get('form_id'): x for x in self.evidence('L3-H-03').get('forms', [])}
        for fid, observation in h3.items():
            if fid not in by_id or observation.get('action_url') != by_id[fid][1].get('action_url'):
                raise ValueError('html_form_action_record_mismatch')
            if (observation.get('relations') != by_id[fid][1].get('relations')
                    or observation.get('current_etld1') != self.doc.get('etld1')
                    or observation.get('action_etld1') != by_id[fid][1].get('action_etld1')):
                raise ValueError('html_form_address_relation_mismatch')
        by_button = {b.get('button_id'): b for b in buttons}
        for post in self.evidence('L3-H-04').get('posts', []):
            declaration = by_button.get(post.get('button_id')) if post.get('button_id') else by_id.get(post.get('form_id'), (None, None))[1]
            action_key = 'effective_action_url' if post.get('button_id') else 'action_url'
            if declaration is None or post.get('destination_url') != declaration.get(action_key) or post.get('form_id') != declaration.get('form_id'):
                raise ValueError('html_post_record_source_mismatch')
            same_site = (post.get('relations') or {}).get('same_site_scope')
            if type(post.get('external')) is bool and (type(same_site) is not bool or post['external'] != (not same_site)):
                raise ValueError('html_post_comparison_not_established')
            if post.get('relations') != declaration.get('relations'):
                raise ValueError('html_post_address_relation_mismatch')
        native_fields = {}
        for index, fact in enumerate(self.record.get('analysis_facts', [])):
            if fact.get('kind') == 'native_form_submission':
                if fact.get('source', {}).get('sha256') != digest(self.html):
                    raise ValueError('html_native_submission_source_mismatch')
                for j, entry in enumerate(fact.get('fields', [])):
                    matches = [(i, f) for i, f in enumerate(inputs) if f.get('field_id') == entry.get('field_id')]
                    if (len(matches) != 1 or entry.get('form_id') != matches[0][1].get('form_id')
                            or entry.get('source_pointer') != f'/html/inputs/{matches[0][0]}'
                            or entry.get('field_id') in native_fields):
                        raise ValueError('html_native_submission_field_mismatch')
                    native_fields[entry.get('field_id')] = (entry, {'source': 'record', 'pointer': f'/analysis_facts/{index}/fields/{j}'})
        selected = []
        self.button_native = {}
        handler_ids = {h.get('html_id') for h in self.html.get('inline_handlers', []) if h.get('html_id')}
        self.handler_ids = handler_ids
        idless_handler_tags = {h.get('tag') for h in self.html.get('inline_handlers', []) if not h.get('html_id')}
        for i, item in enumerate(inputs):
            c = classes.get(item.get('field_id'), {})
            keep = (bool(c.get('credential_type')) or c.get('state') in {'unresolved', 'not_performed'}
                    or item.get('type') == 'password' or item.get('form_id') is not None
                    or item.get('html_id') in handler_ids
                    or (not item.get('html_id') and item.get('tag') in idless_handler_tags))
            # Bind only a captured unique DOM id, never similar name/order or an id-less tag.
            if item.get('tag') in (None, 'input') and item.get('type') in {'submit', 'image', 'button', 'reset'}:
                html_id = item.get('html_id')
                matching = [b for b in buttons if html_id and b.get('html_id') == html_id and b.get('form_id') == item.get('form_id') and b.get('type') == item.get('type')]
                unique = sum(d.get('html_id') == html_id for d in self.html.get('dom_lookup_elements', [])) == 1
                native = native_fields.get(item.get('field_id'))
                if unique and len(matching) == 1 and native:
                    self.button_native[matching[0]['button_id']] = (item, native)
                    keep = bool(c.get('credential_type')) or c.get('state') == 'unresolved'
                else:
                    keep = bool(native and native[0].get('status') in NATIVE and item.get('type') in {'submit', 'image'}) or bool(c.get('credential_type')) or c.get('state') == 'unresolved'
                    keep = keep or item.get('html_id') in handler_ids or (not item.get('html_id') and item.get('tag') in idless_handler_tags)
            if keep:
                selected.append((i, item, c))
            else:
                self.omit(f'/html/inputs/{i}', 'submit role displayed as control, or unclassified unassociated input without recorded event link')
        self.start('입력·폼·기본 제출 경로')
        if inputs and classification.get('state') == 'not_performed':
            self.note('자격정보 분류: 정책 미설정 등으로 수행되지 않음. 입력의 원래 속성은 아래에 표시함.', self.hp('/credential_classification'))
        if inputs and classes and all(c.get('state') == 'evaluated' and not c.get('credential_type') for c in classes.values()):
            self.note('자격정보 분류: 검사한 항목 중 자격정보 종류로 분류된 항목은 없음.', self.hp('/credential_classification'), ids=('L3-H-02',))
        for form_index, form in enumerate(forms):
            fid = form.get('form_id')
            self.begin_item(f'폼 {form_index + 1}', plain=form_declaration(form, [v for v in selected if v[1].get('form_id') == fid]))
            self.note(f'폼 {form_index + 1}', self.hp(f'/forms/{form_index}'), ids=('L3-H-01', 'L3-H-03', 'L3-H-04'))
            for local_index, (i, item, c) in enumerate((v for v in selected if v[1].get('form_id') == fid), 1):
                self.input(local_index, i, item, c, native_fields, indent='  ')
            action, method = form.get('action_url'), form.get('method')
            self.add('기본 제출 방식', method.upper() if method else '미기록', self.hp(f'/forms/{form_index}/method'), indent='  ', public=bool(method))
            if action is not None:
                self.add('기본 제출 주소(action 선언)', action, self.hp(f'/forms/{form_index}/action_url'), indent='  ')
            else:
                self.add('해석하지 못한 action 선언', form.get('action_raw'), self.hp(f'/forms/{form_index}/action_raw'), indent='  ', public=False)
            if form.get('action_resolution') in {'implicit_document', 'empty_document'}:
                self.note('action 속성 부재로 문서 주소를 대상으로 기록함.' if form['action_resolution'] == 'implicit_document' else '빈 action 선언으로 문서 주소를 대상으로 기록함.', self.hp(f'/forms/{form_index}'), indent='  ')
            relation = h3.get(fid, form)
            self.relations(relation, self.hp(f'/forms/{form_index}/relations'), indent='  ')
            for button_index, button in enumerate(buttons):
                if button.get('form_id') != fid:
                    continue
                self.button(button_index, button, form, indent='  ')
        unassociated = [v for v in selected if v[1].get('form_id') is None]
        if unassociated:
            self.note('HTML 구조상 폼 연결이 기록되지 않은 입력:', self.hp('/inputs'))
            for local_index, (i, item, c) in enumerate(unassociated, 1):
                self.begin_item(f'폼 밖 입력 {local_index}', plain=html_field(item))
                self.input(local_index, i, item, c, native_fields, indent='  ')
        for i, button in enumerate(buttons):
            if button.get('form_id') is None:
                if (button.get('type') not in {'submit', 'image'} and button.get('html_id') not in handler_ids
                        and not any(h.get('tag') == 'button' and not h.get('html_id') for h in self.html.get('inline_handlers', []))):
                    self.omit(f'/html/buttons/{i}', 'unassociated non-submit UI control without recorded event relationship')
                    continue
                self.button(i, button, {}, indent='')
        dangling = [v for v in selected if v[1].get('form_id') is not None and v[1]['form_id'] not in by_id]
        if dangling:
            raise ValueError('html_input_unknown_form')
        handlers = self.html.get('inline_handlers') or []
        if handlers:
            causes = [(cid, i) for cid, (i, c) in self.causes.items() if c.get('code') == 'inline_handlers_unanalyzed']
            self.used_causes.update(cid for cid, _ in causes)
            self.note('이벤트 선언(연결·실행 효과는 HTML 단계에서 미해석):', self.hp('/inline_handlers'),
                      *({'source': 'record', 'pointer': f'/causes/{i}'} for _, i in causes), ids=tuple(cid for cid, _ in causes))
            groups = {}
            for i, handler in enumerate(handlers):
                html_id = handler.get('html_id')
                unique = html_id and sum(d.get('html_id') == html_id for d in self.html.get('dom_lookup_elements', [])) == 1
                key = (html_id, handler.get('tag'), handler.get('source')) if unique else ('occurrence', i)
                groups.setdefault(key, []).append((i, handler))
            for number, group in enumerate(groups.values(), 1):
                handler = group[0][1]
                self.begin_item(f'이벤트 선언 {number}', plain=plain('사용자 동작에 연결된 코드 선언', 'HTML에 ' + ' · '.join(h.get('event') or '이벤트' for _, h in group) + ' 동작에 연결된 코드가 선언돼 있습니다. 실제로 실행됐다는 뜻은 아닙니다.'))
                pointers = [self.hp(f'/inline_handlers/{i}') for i, _ in group]
                self.note(f'선언 {number}', *pointers, indent='  ')
                self.add('대상 HTML id' if handler.get('html_id') else 'id 없는 선언의 태그', handler.get('html_id') or handler.get('tag'), *pointers, indent='    ')
                self.add('이벤트', ' · '.join(h.get('event') or '미기록' for _, h in group), *pointers, indent='    ')
                self.add('코드 원문', handler.get('source'), *pointers, indent='    ')
            if idless_handler_tags:
                self.note('id 없는 이벤트 선언과 같은 태그의 입력 속성은 함께 보존하되, 개별 선언과 입력의 동일 요소 대응은 미기록.', self.hp('/inline_handlers'), self.hp('/inputs'))
            self.note('이벤트 선언만으로 입력값이 폼의 숨김 항목으로 전달되거나 전송됐다고 확인할 수 없음.', self.hp('/inline_handlers'))
        if forms or selected or handlers:
            self.note('제출 범위: 기본 주소·컨트롤의 정적 선언. 입력값·선택 상태·검증·컨트롤 활성화와 최종 제출 항목은 미관측.', self.hp('/forms'), self.hp('/inputs'))
            if native_fields:
                self.note('기본 제출 후보는 기록된 name·disabled 조건만 충족한 항목. 폼 소유권, 상위 disabled fieldset, 선택 상태·옵션, 검증·활성화와 핸들러 효과는 모두 확정한 결과가 아님.', {'source': 'record', 'pointer': '/analysis_facts'})
                self.note('기본 제출 제외·조건은 별도 JavaScript의 값 읽기·전송을 제한하는 결론이 아님.', {'source': 'record', 'pointer': '/analysis_facts'})
        self.finish()

    def input(self, local, index, item, c, native_fields, indent):
        pointer = self.hp(f'/inputs/{index}')
        tag = item.get('tag')
        description = (str(tag) + ' 입력 요소') if tag not in (None, 'input') else ('숨김 입력' if item.get('hidden') is True else (str(item.get('type') or '종류 미기록') + '형 입력'))
        kind = c.get('credential_type')
        if kind:
            role = {'username': '사용자명', 'password': '비밀번호'}.get(kind, kind)
            description += ' — 정책이 ' + role + ' 종류로 분류함'
        elif c.get('state') == 'evaluated':
            description += ' — 검사했으나 자격정보 종류가 반환되지 않음'
        elif c.get('state') == 'unresolved':
            description += ' — 자격정보 분류 미확정'
        elif c.get('state') != 'not_performed':
            description += ' — 자격정보 분류 결과 미기록'
        self.note(f'입력 {local}: ' + description, pointer, self.hp('/credential_classification'), ids=('L3-H-02',), indent=indent)
        public_description = (str(tag) + ' 입력 요소') if tag not in (None, 'input') else ('숨김 입력' if item.get('hidden') is True else str(item.get('type') or 'input') + '형 입력')
        if kind:
            public_description += ' — 정책이 ' + {'username': '사용자명', 'password': '비밀번호'}.get(kind, kind) + ' 종류로 분류함'
        self.capture([f'입력 {local}: ' + public_description], [pointer, self.hp('/credential_classification')], ('L3-H-02',), public=True)
        for key, label in [('name', '이름'), ('html_id', 'HTML id'), ('placeholder', '안내 문구'), ('autocomplete', '자동완성 선언')]:
            if item.get(key) is not None and item[key] != '':
                self.add(label, item[key], pointer, indent=indent + '  ')
        if item.get('readonly') is True:
            self.note('readonly 선언 있음; disabled와 다른 속성임.', pointer, indent=indent + '  ', public=True)
        if item.get('disabled') is True:
            self.note('disabled 선언 있음.', pointer, indent=indent + '  ', public=True)
        native = native_fields.get(item.get('field_id'))
        if native and native[0].get('status') in NATIVE:
            self.note('기본 제출 조건: ' + NATIVE[native[0]['status']] + '.', native[1], ids=('L3-native-submission',), indent=indent + '  ', public=True)
            if tag in (None, 'input') and item.get('type') in {'submit', 'image'}:
                self.note('이 입력과 개별 버튼 선언의 DOM 대응은 제공되지 않아 특정 버튼에 결합하지 않음.', pointer, indent=indent + '  ')
        if c.get('state') == 'unresolved':
            for cid, (_, cause) in self.causes.items():
                if cause.get('code') == 'credential_classification_failed' and cause.get('detail', {}).get('target', {}).get('field_id') == item.get('field_id'):
                    self.cause(cid, '분류 한계', indent + '  ')

    def button(self, index, button, form, indent):
        pointer = self.hp(f'/buttons/{index}')
        submit = button.get('type') in {'submit', 'image'}
        self.control_count += 1
        label = f'제출 컨트롤 {self.control_count}' if submit else f'비제출 컨트롤 {self.control_count}'
        if not form:
            self.begin_item(label, plain=html_control(button))
        self.add(label, button.get('text') if button.get('text') else '표시 문구 없음', pointer, ids=('L3-H-04',), indent=indent)
        if button.get('html_id') in self.handler_ids:
            self.add('HTML id', button['html_id'], pointer, indent=indent + '  ')
        if button.get('form_id') is None:
            self.note('폼 연결은 기록되지 않음.', pointer, indent=indent + '  ')
        if button.get('disabled') is True:
            self.note('disabled 선언 있음; 활성 제출을 관측한 결과가 아님.', pointer, indent=indent + '  ', public=True)
        native_binding = self.button_native.get(button.get('button_id'))
        if native_binding:
            item, native = native_binding
            if item.get('name'):
                self.add('제출 항목 이름', item['name'], native[1], indent=indent + '  ')
            if native[0].get('status') in NATIVE:
                self.note('기본 제출 조건: ' + NATIVE[native[0]['status']] + '.', native[1], ids=('L3-native-submission',), indent=indent + '  ', public=True)
        if not submit:
            return
        action, method = button.get('effective_action_url'), button.get('effective_method')
        if form and action == form.get('action_url') and method == form.get('method') and action is not None:
            self.note('기록된 제출 방식·대상은 폼 기본 경로와 같음.', pointer, indent=indent + '  ', public=True)
        else:
            if method != form.get('method') or not form:
                self.add('컨트롤의 제출 방식', method.upper() if method else '미기록', pointer, indent=indent + '  ')
            if action is None:
                self.add('해석하지 못한 컨트롤 대상 선언', button.get('formaction_raw'), pointer, indent=indent + '  ')
            elif action != form.get('action_url') or not form:
                self.add('컨트롤의 제출 주소', action, pointer, indent=indent + '  ')
                self.relations(button, pointer, indent=indent + '  ')

    def brand(self):
        self.start('브랜드 정책·리소스 관계')
        # Confidence is an uncalibrated producer label, retained in the record.
        # It neither establishes identity nor distinguishes displayed grounds.
        identity_keys = ('detected_brand', 'brand_identification_sources', 'brand_policy_provider', 'brand_policy_entity_id')
        shared_identity = bool(self.evidence('L3-H-05')) and bool(self.evidence('L3-H-06')) and all(self.evidence('L3-H-05').get(k) == self.evidence('L3-H-06').get(k) for k in identity_keys)
        if all(k in self.signals for k in ('L3-H-05', 'L3-H-06')) and all(self.evidence('L3-H-05').get(k) == self.evidence('L3-H-06').get(k) for k in identity_keys):
            for code in ('brand_not_identified', 'brand_identifier_not_configured'):
                occurrences = []
                for sid in ('L3-H-05', 'L3-H-06'):
                    found = [(cid, self.causes[cid][0]) for cid in self.signals[sid][1].get('cause_ids', [])
                             if cid in self.causes and self.causes[cid][1].get('code') == code and self.causes[cid][1].get('detail') == {'code': code}]
                    if len(found) == 1:
                        occurrences.extend(found)
                if len(occurrences) == 2:
                    self.add('문서 도메인·리소스 묶음 대조 한계', '두 대조에서 각각 ' + LIMITS[code],
                             *({'source': 'record', 'pointer': f'/causes/{i}'} for _, i in occurrences), ids=tuple(cid for cid, _ in occurrences))
                    self.used_causes.update(cid for cid, _ in occurrences)
        identities = []
        for sid, label in [('L3-H-05', '문서 도메인 대조'), ('L3-H-06', '리소스 묶음 대조')]:
            e = self.evidence(sid)
            if not e:
                self.signal_limits(sid, label + ' 한계')
                continue
            if 'brand_identification_confidence' in e:
                self.omit(self.rp(sid, '/evidence/brand_identification_confidence')['pointer'],
                          'uncalibrated producer label; preserve per occurrence in native/record/audit, show recorded selection grounds instead', 'record')
            identity = {k: e.get(k) for k in identity_keys}
            if identity not in identities:
                if e.get('detected_brand'):
                    self.begin_item('문서·리소스 브랜드 대조' if shared_identity else label, basis='policy_comparison',
                                    plain=plain('페이지의 브랜드 표시와 참조 자료', f"정책은 페이지에 적힌 표시를 {e['detected_brand']} 브랜드로 분류했습니다."))
                    identity_sids = ('L3-H-05', 'L3-H-06') if shared_identity else (sid,)
                    self.add('문서·리소스 대조에 선택된 브랜드' if shared_identity else label + '에 선택된 브랜드',
                             e['detected_brand'], *(self.rp(s, '/evidence/detected_brand') for s in identity_sids),
                             ids=identity_sids)
                    grounds = e.get('brand_identification_sources')
                    positions = ', '.join(BRAND_SOURCE_LABELS.get(value, value + ' (근거 종류 미해석)') for value in grounds) if grounds else '위치가 기록되지 않음'
                    self.add('브랜드 선택 근거로 기록된 위치', positions,
                             *(self.rp(s, '/evidence/brand_identification_sources') for s in identity_sids), ids=identity_sids)
                    if e.get('brand_policy_provider'):
                        self.add('분석에 기록된 브랜드 정보 출처', e['brand_policy_provider'],
                                 *(self.rp(s, '/evidence/brand_policy_provider') for s in identity_sids), ids=identity_sids)
                identities.append(identity)
            result = self.signals[sid][1].get('detected')
            if sid == 'L3-H-05' and type(result) is bool:
                if not e.get('detected_brand') or not e.get('current_domain') or not e.get('expected_domains') or e['current_domain'] != self.doc.get('etld1'):
                    raise ValueError('html_brand_domain_comparison_not_established')
                if result:
                    self.current_item['plain']['text'] += ' 문서의 등록 도메인이 해당 브랜드 정책의 참조 도메인과 맞지 않습니다.'
                    self.note(label + ': ICANN 등록 도메인 기준으로 정책 참조 도메인과 불일치.', self.rp(sid, '/detected'), ids=(sid,), public=True)
                    self.add('실제로 대조한 문서 등록 도메인', e.get('current_domain'), self.rp(sid))
                    for value in e.get('expected_domains', []):
                        self.add('정책 참조 도메인', value, self.rp(sid, '/evidence/expected_domains'))
                else:
                    self.current_item['plain']['text'] += ' 문서의 등록 도메인이 해당 브랜드 정책의 참조 도메인과 맞습니다.'
                    self.add('문서 도메인 대조', '문서의 ICANN 등록 도메인 ' + e['current_domain'] + '이 정책 참조 도메인과 일치.', self.rp(sid), ids=(sid,))
                    self.omit(self.rp(sid)['pointer'] + '/expected_domains', 'known match; do not repeat reference inventory', 'record')
            self.signal_limits(sid, label + ' 한계')
        selected_sids = tuple(sid for sid in ('L3-H-05', 'L3-H-06') if self.evidence(sid).get('detected_brand'))
        if selected_sids:
            self.note('선택된 브랜드는 주소 대조의 기준이며, 이 결과만으로 실제 운영자나 사칭 여부가 확인되지는 않음.',
                      *(self.rp(sid, '/evidence/detected_brand') for sid in selected_sids), ids=selected_sids)
        resources = self.evidence('L3-H-06').get('resources')
        if resources is not None:
            # Check the supplied policy bundle against recorded declarations, without
            # computing new domains or invoking the evaluator in the Builder.
            expected = [('image', v.get('resource_url'), v.get('resource_domain')) for v in self.html.get('images') or []]
            favicon = self.html.get('favicon')
            if favicon:
                expected.append(('favicon', favicon.get('resource_url'), favicon.get('resource_domain')))
            # Open Graph is a mapping: JSON storage can reorder its keys without
            # changing any observation. Keep image/favicon occurrence checks,
            # but compare metadata by property name and URL, including counts.
            expected_metadata = sorted((k, v.get('resource_url')) for k, v in
                                       (self.html.get('open_graph') or {}).items() if v.get('resource_url'))
            observed_metadata = sorted((r.get('resource_type'), r.get('resource_url'))
                                       for r in resources[len(expected):])
            if (len(expected) + len(expected_metadata) != len(resources)
                    or observed_metadata != expected_metadata
                    or any((r.get('resource_type'), r.get('resource_url')) != x[:2]
                           or (x[2] is not None and r.get('resource_domain') != x[2])
                           for r, x in zip(resources, expected))):
                raise ValueError('html_brand_resource_bundle_source_mismatch')
        declarations = []
        for i, image in enumerate(self.html.get('images') or []):
            declarations.append(('이미지', image.get('resource_url'), image.get('src_raw'), image.get('alt'), self.hp(f'/images/{i}')))
        favicon = self.html.get('favicon')
        if favicon:
            declarations.append(('favicon', favicon.get('resource_url'), favicon.get('raw_href'), None, self.hp('/favicon')))
        for key, value in (self.html.get('open_graph') or {}).items():
            if value.get('resource_url'):
                declarations.append((key, value['resource_url'], value.get('raw_content'), None, self.og(key)))
        # Share exact addresses while retaining the declaration roles and alt distinctions.
        groups = {}
        for role, url, literal, alt, pointer in declarations:
            groups.setdefault((url, literal if url is None else None), []).append((role, alt, pointer))
        for (url, literal), roles in groups.items():
            role = '·'.join(dict.fromkeys(r for r, _, _ in roles))
            value = url if url is not None else literal
            if isinstance(value, str) and value.startswith('data:') and len(value) > 300:
                value = value.split(',', 1)[0] + ',… (자료 URI 원문은 내부 보존; 내용 미관측)'
                for _, _, p in roles:
                    self.omit(p['pointer'], 'embedded resource bytes retained in raw/audit, no visual interpretation')
            self.begin_item(f'리소스 주소 {len(self.items) + 1}', plain=plain('페이지에 적힌 이미지·공유 자료 주소', f'{role} 자료의 주소로 {value}가 선언돼 있습니다. 실제 로드나 내용을 확인한 결과는 아닙니다.'))
            self.add(role + (' 주소 선언' if url is not None else ' 원문 주소 선언(HTTP 주소 미해석)'), value,
                     *(p for _, _, p in roles), ids=('L3-H-06',))
            for alt in dict.fromkeys(a for _, a, _ in roles if a):
                self.add('해당 주소 이미지의 대체 텍스트', alt, *(p for _, a, p in roles if a == alt))
        if 'L3-H-06' in self.signals:
            result = self.signals['L3-H-06'][1].get('detected')
            if type(result) is bool:
                self.begin_item('리소스 묶음 대조', basis='policy_comparison',
                                plain=plain('페이지 자료 묶음과 참조 정책', '이미지·아이콘·공유 자료 주소 묶음을 정책과 대조했고, ' + ('묶음 불일치가 반환됐습니다.' if result else '묶음 불일치가 반환되지 않았습니다.')))
                self.note('리소스 묶음 대조: 정책이 묶음 불일치를 반환함.' if result else '리소스 묶음 대조: 정책이 묶음 불일치를 반환하지 않음.', self.rp('L3-H-06', '/detected'), ids=('L3-H-06',), public=True)
            if resources is not None and (declarations or type(result) is bool):
                self.note('리소스 대조 범위: 정책에 제공된 이미지·favicon·URL형 공유 메타데이터 묶음. 결과를 개별 리소스 판정으로 나누지 않음.', self.rp('L3-H-06', '/evidence/resources'))
        if declarations:
            self.note('리소스 주소·대체 텍스트는 HTML 선언. 픽셀·실제 로드·리소스 내용을 관측한 결과가 아님.', self.hp('/images'), self.hp('/favicon'))
        self.finish()

    def navigation(self):
        self.start('링크·내장 문서 선언')
        for i, link in enumerate(self.html.get('links') or []):
            pointer = self.hp(f'/links/{i}')
            literal, url = link.get('href_raw'), link.get('destination_url')
            if (isinstance(literal, str) and literal.startswith('#') and
                    self.doc.get('effective_base_url') == self.doc.get('url') and
                    link.get('download') is None and link.get('target') is None):
                self.omit(pointer['pointer'], 'same-document fragment UI declaration; no additional destination or download distinction')
                continue
            self.begin_item(f'링크 {i + 1}', plain=html_link(link))
            self.add(f'링크 {i + 1} 표시 문구', link.get('text') or '표시 문구 없음', pointer)
            self.add('대상 주소' if url is not None else 'HTTP 주소로 해석하지 못한 href 선언', url if url is not None else literal, pointer, indent='  ')
            if link.get('download') is not None:
                self.add('download 속성 선언', link['download'] if link['download'] else '빈 문자열로 선언됨', pointer, indent='  ')
            if link.get('target') is not None:
                self.add('target 선언', link['target'], pointer, indent='  ')
        for i, frame in enumerate(self.html.get('frames') or []):
            pointer = self.hp(f'/frames/{i}')
            self.begin_item(f'내장 문서 {i + 1}', plain=html_frame(frame))
            self.note(f'내장 문서 {i + 1}', pointer)
            if frame.get('source_url') is not None:
                self.add('src 주소 선언', frame['source_url'], pointer, indent='  ')
            elif frame.get('src_raw') is not None:
                self.add('HTTP 주소로 해석하지 못한 src 선언', frame['src_raw'], pointer, indent='  ')
            if frame.get('srcdoc') is not None:
                self.quote('srcdoc 원문 선언', frame['srcdoc'], pointer)
            if frame.get('content_observed') is False:
                self.note('내장 문서의 실제 로드·렌더링은 미관측. srcdoc 원문은 재분석하지 않음.', pointer, indent='  ')
        if self.lines:
            self.note('링크 클릭·다운로드와 내장 문서 실행은 관측하지 않음.', self.hp('/links'), self.hp('/frames'))
        self.finish()
        refresh = self.html.get('meta_refresh')
        if refresh:
            self.start('HTML 이동 지시')
            self.begin_item('meta refresh', plain=html_refresh(refresh))
            if refresh.get('valid') is True:
                self.add('meta refresh 지연(초)', refresh.get('delay_seconds'), self.hp('/meta_refresh/delay_seconds'), ids=('L3-H-07',))
                if refresh.get('target_url') is not None:
                    self.add('이동 대상 선언', refresh['target_url'], self.hp('/meta_refresh/target_url'))
                else:
                    self.note('별도 이동 대상은 선언되지 않음.', self.hp('/meta_refresh/target_raw'))
            else:
                self.add('해석하지 못한 meta refresh 선언', refresh.get('raw_content'), self.hp('/meta_refresh/raw_content'), ids=('L3-H-07',))
                if refresh.get('target_raw') is not None:
                    self.add('해석하지 못한 대상 원문', refresh['target_raw'], self.hp('/meta_refresh/target_raw'))
            self.note('HTML의 이동 지시이며 실제 이동·대상 응답을 관측한 결과가 아님.', self.hp('/meta_refresh'))
            self.finish()

    def errors(self):
        self.start('HTML 관측·분석 한계')
        for cid, (_, cause) in self.causes.items():
            occurrence = cause.get('occurrence') or {}
            detail = cause.get('detail') or {}
            stage = occurrence.get('stage') or detail.get('stage')
            relevant = (any(x in HTML_IDS for x in occurrence.get('affected_signal_ids', []))
                        or stage in {'html_parsing', 'html_analysis', 'credential_classification', 'page_collection'}
                        or cause.get('code', '').startswith('html_'))
            if (cause.get('code') == 'analysis_unresolved_reason_not_recorded'
                    and set(occurrence.get('affected_signal_ids', [])) <= {'L3-H-01', 'L3-H-02'}
                    and (self.html.get('credential_classification') or {}).get('state') == 'not_performed'):
                self.omit(f'/causes/{self.causes[cid][0]}', 'normalization placeholder; actual recorded classification non-performance shown with inputs', 'record')
                continue
            affected = set(occurrence.get('affected_signal_ids', []))
            invalid = {'L3-H-07': (self.html.get('meta_refresh') or {}).get('valid') is False,
                       'L3-H-08': (self.html.get('base') or {}).get('valid') is False}
            if (cause.get('code') == 'analysis_unresolved_reason_not_recorded' and affected
                    and affected <= set(invalid) and all(invalid[sid] for sid in affected)):
                self.omit(f'/causes/{self.causes[cid][0]}', 'normalization placeholder; recorded invalid declaration and unresolved relationship already shown at its subject', 'record')
                continue
            if relevant and not detail.get('script_id'):
                self.cause(cid, '관측 한계')
        self.finish()

    def build(self):
        self.subject()
        self.page()
        self.forms()
        self.brand()
        self.navigation()
        self.errors()
        for sid in HTML_IDS:
            if sid in self.signals:
                self.omit(self.rp(sid, '')['pointer'], 'signal status/counts/representative values remain internal; facts rendered at their subjects', 'record')
        return self.blocks


def build_html_text_context(record, raw, *, native=None, audit=None,
                            text_chars=DEFAULT_TEXT_CHARS, max_bytes=DEFAULT_MAX_BYTES):
    """Build the explicitly HTML-only model body from supplied recorded facts."""
    from .model_text import TextContext
    if record.get('layer') != 'l3':
        raise ValueError('html_context_requires_l3_record')
    if type(text_chars) is not int or text_chars < 3:
        raise ValueError('html_text_quotation_limit_invalid')
    if type(max_bytes) is not int or max_bytes < 1:
        raise ValueError('html_text_body_limit_invalid')
    validate_input_bundle([record], {'l3': raw})
    validate_native_input(record, raw, native)
    builder = _HTML(record, raw, text_chars)
    blocks = builder.build()
    body, mapping = assemble(blocks)
    if len(body.encode('utf-8')) > max_bytes:
        raise ValueError('html_text_context_budget_exceeded')
    source = {'evidence': [{'id': s['id'], 'kind': 'html_record', 'facts': deepcopy(s)}
                           for s in record.get('signals', [])],
              'html_raw': deepcopy(raw), 'html_record': deepcopy(record),
              'html_native': deepcopy(native), 'line_map': builder.line_map,
              'model_omissions': builder.omissions,
              'unreviewed_layers': ['l3_javascript'],
              'html_review_input': {'records': [deepcopy(record)], 'raws': {'l3': deepcopy(raw)},
                                    'native': deepcopy(native), 'text_chars': text_chars, 'max_bytes': max_bytes},
              'selection_contract': {'scope': 'html', 'producer_scope': 'first base/refresh/favicon; last repeated OG property',
                                     'text_selection': 'complete within bound, otherwise source-order head/tail',
                                     'brand_presentation': 'comparison target and recorded grounds; confidence retained internally, no ownership or impersonation conclusion',
                                     'javascript': 'outside explicitly selected HTML view; full input preserved'}}
    result = TextContext(body, blocks, mapping, source, VERSION)
    if audit is not None:
        audit.update(result.audit())
    return result


def validate_html_text_document(document):
    """Reproduce selection at the wire boundary; reject appended JSON or edits."""
    from .model_text import build_text_context
    inputs = document.source_context.get('html_review_input')
    if inputs is None:
        raise ValueError('html_text_missing_review_input')
    record = next((r for r in inputs['records'] if r['layer'] == 'l3'), None)
    if record is None:
        raise ValueError('html_context_requires_l3_record')
    for key, expected in [('html_raw', inputs['raws']['l3']), ('html_record', record), ('html_native', inputs.get('native'))]:
        if canonical(document.source_context.get(key)) != canonical(expected):
            raise ValueError('html_audit_input_binding_changed:' + key)
    validate_native_input(record, inputs['raws']['l3'], inputs.get('native'))
    rebuilt = build_text_context(inputs['records'], inputs['raws'], l3_scope='html',
                                 html_text_chars=inputs['text_chars'], html_max_bytes=inputs['max_bytes'])
    if (document.version != VERSION or document.body != rebuilt.body or [asdict(b) for b in document.blocks] != [asdict(b) for b in rebuilt.blocks]
            or document.source_map != rebuilt.source_map):
        raise ValueError('html_reviewed_body_or_mapping_changed')
    for key in ('line_map', 'model_omissions', 'selection_contract', 'evidence', 'base_selected_context', 'unreviewed_layers'):
        if canonical(document.source_context.get(key)) != canonical(rebuilt.source_context.get(key)):
            raise ValueError('html_audit_selection_changed:' + key)
    return document
