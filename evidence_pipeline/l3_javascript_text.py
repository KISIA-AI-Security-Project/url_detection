"""Source-bound JavaScript context: recorded static relationships, never execution."""
from copy import deepcopy
from dataclasses import asdict
import json
import re
from urllib.parse import urlsplit

from .records import canonical
from .l3_html_text import assemble, validate_input_bundle, validate_native_input
from .text_blocks import TextBlock, field

VERSION = 'l3-javascript-text-1'
JS_IDS = tuple(f'L3-J-{i:02d}' for i in range(1, 10))
EVENTS = ('dynamic_execution', 'decode_operations', 'script_injection', 'network_requests',
          'credential_access', 'redirects', 'environment_access', 'branches')
POLICIES = {
    'dynamic_execution_policy_configured': '동적 API 목록',
    'decode_policy_configured': '문자열 변환 목록',
    'credential_policy_configured': '인증 입력 분류',
    'network_policy_configured': '요청 API 목록',
    'redirect_policy_configured': '이동 API 목록',
    'anti_bot_policy_configured': '환경 속성 목록',
    'branch_behavior_policy_configured': '분기 동작 비교',
}
STATUS = {
    'parsed': '확보한 원문을 구문 분석함',
    'missing_source': '원문 미확보; 이 스크립트의 동작은 미분석',
    'data_block': '종류 선언에 따라 JavaScript 구문 분석 대상에서 제외됨',
    'source_limit_exceeded': '원문은 있으나 크기 제한으로 구문 분석하지 않음',
    'parser_unavailable': '원문은 있으나 구문 분석기를 사용할 수 없음',
    'parse_error': '원문은 있으나 구문 분석에 실패함',
}
LIMITS = {
    'javascript_source_unavailable': '스크립트 원문을 확보하지 못함',
    'javascript_parse_error': 'JavaScript 구문 분석 실패',
    'javascript_parser_unavailable': 'JavaScript 구문 분석기 사용 불가',
    'javascript_source_limit_exceeded': '스크립트 구문 분석 크기 제한',
    'javascript_event_limit_exceeded': '정적 관측 개수 제한으로 일부 결과가 보존되지 않음',
    'javascript_analysis_limit': '정적 분석의 노드 또는 재귀 제한',
    'script_order_unresolved': 'module·async·defer의 연결 및 실행 순서를 확정하지 못함',
    'callback_parameters_unresolved': '함수 인자 또는 콜백 호출의 실제 값이 미확인',
    'function_call_depth_limit': '함수 호출 연결의 분석 깊이 제한',
    'function_return_value_unresolved': '함수 반환값과 블록 사이 종료 흐름을 완전히 해석하지 않음',
    'throw_control_flow_unresolved': '예외로 인한 제어 흐름을 완전히 해석하지 않음',
    'conditional_value_unresolved': '조건에 따라 값이 달라짐; 선택된 경로와 최종 값은 미확인',
    'branch_reachability_not_evaluated': '조건에 따른 실제 경로 선택은 미확인',
    'loop_execution_not_modeled': '반복 횟수와 전체 반복 제어 흐름은 미해석',
    'css_selector_unresolved': 'DOM 선택자가 미해석',
    'dom_collection_unresolved': 'DOM 목록의 구체적 요소 연결은 미해석',
    'fetch_options_unresolved': '요청 옵션의 필드 연결은 미해석',
    'fetch_request_unresolved': '요청 설정의 유효성 또는 전달 인자 연결은 미확정',
    'fetch_payload_conversion_unresolved': '요청 인자 객체의 실제 전달 형식 변환은 미해석',
    'object_write_unresolved': '객체 쓰기 대상과 값의 관계는 미해석',
    'object_read_unresolved': '객체 읽기 대상과 값의 관계는 미해석',
    'object_structure_unresolved': '객체 구조의 일부는 미해석',
    'source_sink_or_destination_unresolved': '입력 읽기와 요청의 연결 또는 목적지 관계는 미확정',
    'network_destination_unresolved': '요청 구문은 있으나 전체 목적지 주소는 미확정',
    'credential_classification_failed': '일부 HTML 입력의 인증 종류 분류 실패',
    'unsupported_script_content_type': '외부 응답을 JavaScript 소스로 채택하지 않음',
    'external_script_limit_exceeded': '외부 스크립트 수집 개수 제한',
    'script_request_timeout': '외부 스크립트 요청 시간 초과',
    'script_dns_resolution_failed': '외부 스크립트 주소의 DNS 조회 실패',
    'script_connection_failed': '외부 스크립트 연결 실패',
    'script_target_policy_blocked': '외부 스크립트 수집 대상이 설정된 접근 범위에서 제외됨',
    'decoding_loss': '문자 디코딩 중 원문 손실 기록',
    'unknown_encoding': '응답 문자 인코딩 미해석',
}
POSITIONS = {'url': '주소 인자', 'body': '본문 인자', 'headers': '헤더 인자', 'request_argument': '요청 인자'}
CREDENTIALS = {'password': '비밀번호', 'username': '사용자명', 'email': '이메일'}
WRAPPERS = {'javascript_analysis_unavailable', 'javascript_analysis_incomplete', 'javascript_relationship_unresolved'}
STANDARD_MESSAGES = {
    'javascript_source_unavailable': 'Script source is unavailable to analysis; consult collection_errors for attempted, failed or limited acquisition.',
    'callback_parameters_unresolved': 'Callback arguments and invocation unobserved; parameters do not inherit outer bindings',
    'function_return_value_unresolved': 'Exit statement retained; full inter-block exit and return-value propagation are not modeled',
    'throw_control_flow_unresolved': 'Exit statement retained; full inter-block exit and return-value propagation are not modeled',
    'branch_reachability_not_evaluated': 'Condition retained; dynamic path feasibility was not evaluated',
    'loop_execution_not_modeled': 'Loop condition retained; loop iterations and full control flow are not evaluated',
    'conditional_value_unresolved': 'Branches produce different values; candidate values retained, selected branch unobserved',
    'script_order_unresolved': 'Module/async/defer binding and execution order not established',
    'function_call_depth_limit': 'Static function call depth exceeded',
    'javascript_parser_unavailable': 'The esprima dependency is required for structural parsing.',
    'javascript_source_limit_exceeded': 'Script source exceeds the configured analysis limit.',
    'javascript_event_limit_exceeded': 'Static observation output exceeded the configured event limit.',
}


def pointer(path, source='raw'):
    return {'source': source, 'pointer': path}


def unique(values):
    return list(dict.fromkeys(values))


from .presentation_items import PresentationCapture
from .public_explanations import javascript_event


class _JS(PresentationCapture):
    def __init__(self, record, raw, text_chars):
        self.record, self.raw, self.text_chars = record, raw, text_chars
        self.js = raw.get('javascript') or {}
        self.analysis = self.js.get('analysis') or {}
        self.html = raw.get('html') or {}
        self.signals = {s['id']: (i, s) for i, s in enumerate(record.get('signals', [])) if s['id'] in JS_IDS}
        if len(self.signals) != len([s for s in record.get('signals', []) if s['id'] in JS_IDS]):
            raise ValueError('duplicate_javascript_signal')
        self.scripts = {}
        for i, script in enumerate(self.js.get('scripts') or []):
            sid = script.get('script_id')
            if not sid or sid in self.scripts:
                raise ValueError('javascript_script_identity_ambiguous')
            self.scripts[sid] = (i, script)
        self.index = {}
        for kind in EVENTS:
            for i, event in enumerate(self.js.get(kind) or []):
                self.validate_event(event)
                self.index.setdefault((kind, event.get('event_id')), []).append((i, event))
        self.reads = list(self.js.get('credential_access') or [])
        self.read_sources = [self.jp(f'/credential_access/{i}') for i in range(len(self.reads))]
        self.dom_reads_selected = set()
        for i, event in enumerate(self.js.get('dom_access') or []):
            if not (event.get('access_type') == 'value_read' and event.get('credential_type')
                    and event.get('field_id') and event.get('event_id')):
                continue
            existing = self.index.get(('credential_access', event['event_id']), [])
            if existing:
                if any(canonical(original) != canonical(event) for _, original in existing):
                    raise ValueError('javascript_preserved_read_identity_conflict')
                continue
            # The event cap can retain the same classified read only in dom_access.
            # Select the explicit original occurrence; do not reconstruct missing ones.
            self.validate_event(event)
            read_index = len(self.reads)
            self.reads.append(event)
            self.read_sources.append(self.jp(f'/dom_access/{i}'))
            self.index.setdefault(('credential_access', event['event_id']), []).append((read_index, event))
            self.dom_reads_selected.add(i)
        self.blocks, self.lines, self.ids, self.line_map, self.omissions = [], [], [], [], []
        self.used_causes, self.quoted, self.quote_spans, self.destinations_seen = set(), {}, [], {}
        self.credential_labels = {e['event_id']: f'입력 읽기 {i + 1}' for i, e in enumerate(self.reads)}
        self.decode_used = set()
        self.validate_record_binding()

    def jp(self, path):
        return pointer('/javascript' + path)

    def rp(self, sid, path='/evidence'):
        return pointer(f'/signals/{self.signals[sid][0]}' + path, 'record')

    def evidence(self, sid):
        return self.signals.get(sid, (None, {}))[1].get('evidence') or {}

    def validate_source(self, event):
        sid = event.get('script_id')
        if sid not in self.scripts:
            raise ValueError('javascript_event_script_missing')
        script = self.scripts[sid][1]
        source, span = script.get('source'), event.get('source_range')
        if (not isinstance(source, str) or not isinstance(span, list) or len(span) != 2
                or any(type(v) is not int for v in span) or not 0 <= span[0] <= span[1] <= len(source)):
            raise ValueError('javascript_event_source_range_invalid')
        if event.get('source_excerpt') is not None and event['source_excerpt'] != source[span[0]:span[1]][:300]:
            raise ValueError('javascript_event_excerpt_source_mismatch')

    def validate_event(self, event):
        self.validate_source(event)
        if event.get('execution_observed') is not False or event.get('origin') != 'static':
            raise ValueError('javascript_event_observation_scope_mismatch')

    def validate_record_binding(self):
        target = self.record.get('target') or {}
        if self.analysis.get('document_url') is not None and target.get('document_url') is not None:
            if self.analysis['document_url'] != target['document_url']:
                raise ValueError('javascript_document_subject_mismatch')
        coverage = self.record.get('coverage') or {}
        for key, raw_key in [('javascript_source_complete', 'source_complete'),
                             ('javascript_semantic_complete', 'semantic_complete'),
                             ('javascript_decoding_complete', 'decoding_complete'),
                             ('javascript_parsed_count', 'parsed_script_count')]:
            if key in coverage and raw_key in self.analysis and coverage[key] != self.analysis[raw_key]:
                raise ValueError('javascript_observation_scope_mismatch:' + key)
        specifications = [
            ('L3-J-01', 'dynamic_execution', 'execution_count', 'apis', 'api'),
            ('L3-J-03', 'script_injection', 'script_count', 'urls', 'url'),
            ('L3-J-05', 'credential_access', 'access_count', 'fields', 'field_id'),
            ('L3-J-08', 'environment_access', 'check_count', 'properties', 'property'),
        ]
        for sid, kind, count_key, list_key, event_key in specifications:
            e, events = self.evidence(sid), self.js.get(kind) or []
            expected = unique([v[event_key] for v in events if v.get(event_key)])
            if ((count_key in e and e[count_key] != len(events)) or (list_key in e and e[list_key] != expected)):
                raise ValueError('javascript_record_summary_source_mismatch:' + sid)
        known_requests = [e for e in self.js.get('network_requests') or [] if e.get('destination_url')]
        expected = [{'url': e.get('destination_url'), 'etld1': e.get('destination_etld1'), 'external': e.get('external')}
                    for e in known_requests]
        if 'destinations' in self.evidence('L3-J-04') and self.evidence('L3-J-04')['destinations'] != expected:
            raise ValueError('javascript_network_record_source_mismatch')
        contexts = [{key: deepcopy(event[key]) for key in
                     ('event_id', 'script_id', 'source_range', 'call_context', 'control_context', 'request_context')}
                    for event in self.js.get('network_requests') or [] if event.get('request_context')]
        if canonical(self.evidence('L3-J-04').get('request_contexts', [])) != canonical(contexts):
            raise ValueError('javascript_request_context_record_source_mismatch')
        relationships = {
            'L3-J-02': ('linked_execution_events', [e for e in self.js.get('dynamic_execution') or [] if e.get('decode_links')]),
            'L3-J-06': ('source_sink_relationships', [{'request': e, 'link': link}
                           for e in self.js.get('network_requests') or [] if e.get('external') is True
                           for link in e.get('source_links') or []]),
            'L3-J-07': ('redirect_observations', self.js.get('redirects') or []),
        }
        for sid, (key, expected) in relationships.items():
            if key in self.evidence(sid) and canonical(self.evidence(sid)[key]) != canonical(expected):
                raise ValueError('javascript_relationship_record_source_mismatch:' + sid)
        for comparison in self.evidence('L3-J-09').get('branch_comparisons') or []:
            if comparison.get('event') not in (self.js.get('branches') or []):
                raise ValueError('javascript_branch_record_source_mismatch')

    def start(self, title):
        self.title, self.lines, self.ids = title, [], []
        self.reset_items()

    def add(self, label, value, *sources, ids=(), indent='', public=True):
        for line in field(label, value):
            rendered = indent + re.sub(r'\r\n|\r|\n', lambda m: m.group() + indent, line)
            self.lines.append(rendered)
            self.line_map.append({'title': self.title, 'line_in_block': len(self.lines), 'text': rendered, 'sources': list(sources)})
            self.capture([rendered], sources, ids, public=public and value is not None)
        self.ids.extend(ids)

    def note(self, text, *sources, ids=(), indent='', public=False):
        self.lines.append(indent + text)
        self.line_map.append({'title': self.title, 'line_in_block': len(self.lines), 'text': indent + text, 'sources': list(sources)})
        self.ids.extend(ids)
        self.capture([indent + text], sources, ids, public=public)

    def finish(self):
        if self.lines:
            self.blocks.append(TextBlock(self.title, self.lines, tuple(dict.fromkeys(self.ids)),
                                         [v for v in self.items if v['lines']]))

    def omit(self, path, reason, source='raw', **extra):
        self.omissions.append({'source': source, 'pointer': path, 'reason': reason, **extra})

    def quote(self, label, value, *sources, indent='  ', source_text=True):
        if len(value) <= self.text_chars:
            self.add(label, value, *sources, indent=indent)
            return
        head = self.text_chars * 2 // 3
        tail = self.text_chars - head
        self.add(label + ' (앞부분)', value[:head], *sources, indent=indent)
        self.add(label + ' (뒷부분)', value[-tail:], *sources, indent=indent)
        self.note('인용 중간은 이 본문에서 생략함; 전체 원문은 내부 자료에 보존됨.' if source_text
                  else '구문 요약 중간은 이 본문에서 생략함; 전체 구조화 기록은 내부 자료에 보존됨.', *sources, indent=indent)
        for p in sources:
            extra = {} if source_text else {'range_basis': 'formatted_branch_observation', 'formatted_value': value}
            self.omit(p['pointer'], 'bounded source quotation; full source retained' if source_text
                      else 'bounded branch observation presentation; full observation retained',
                      p['source'], omitted_range=[head, len(value)-tail], **extra)

    def location(self, event):
        index, script = self.scripts[event['script_id']]
        lo, hi = event['source_range']
        first = script['source'].count('\n', 0, lo) + 1
        last = script['source'].count('\n', 0, max(lo, hi-1)) + 1
        return f'스크립트 {index + 1}, ' + (f'{first}행' if first == last else f'{first}~{last}행')

    def resolve(self, kind, event_id):
        found = self.index.get((kind, event_id), [])
        return found[0] if len(found) == 1 else None

    def event(self, kind, index, label, ids=(), *, code=True):
        e = self.reads[index] if kind == 'credential_access' else self.js[kind][index]
        explanation = javascript_event(kind, e)
        if kind == 'network_requests':
            key = canonical({k: e.get(k) for k in ('destination_url', 'destination_prefix',
                             'destination_candidates', 'relations', 'external')})
            if e.get('destination_url') and key in self.destinations_seen:
                first, _ = self.destinations_seen[key]
                explanation['text'] = f'코드에 앞의 요청 구문 {first + 1}과 같은 주소·사이트 관계로 요청하는 구문이 있습니다. 실행 결과가 아닌 정적 코드 분석에서 확인한 내용입니다.'
        self.begin_item(label, basis='static_relation', plain=explanation)
        p = self.read_sources[index] if kind == 'credential_access' else self.jp(f'/{kind}/{index}')
        self.add(label, self.location(e), p, ids=ids)
        self.context(e, p)
        if kind == 'network_requests':
            self.request_context(e, p)
        if code:
            if kind == 'credential_access':
                self.reading_code(e, p)
            else:
                self.code(e, p)
        return e, p

    def request_context(self, event, p):
        context = event.get('request_context')
        if not context:
            return
        if context.get('schema_version') != 'request-context-1' or context.get('execution_observed') is not False:
            raise ValueError('javascript_request_context_scope_mismatch')
        # Relationships are produced by L3 and bound to J04 above. The Builder
        # selects their meaning and limits; it never parses surrounding source.
        source = self.scripts[event['script_id']][1]['source']
        def check(fragment):
            span = fragment.get('source_range')
            if (not isinstance(span, list) or len(span) != 2 or not all(type(n) is int for n in span)
                    or not 0 <= span[0] < span[1] <= len(source)
                    or source[span[0]:span[1]] != fragment.get('source_excerpt')):
                raise ValueError('javascript_request_context_source_mismatch')
        cp = self.jp(p['pointer'][len('/javascript'):] + '/request_context')
        if context.get('binding_scope_unresolved'):
            self.add('주변 식별자 관계', 'with 구문의 이름 해석 대상이 미확정이므로 콜백·응답 관계를 연결하지 않음', cp, indent='  ')
            self.plain_note('with 구문 안의 이름이 어느 객체를 가리키는지 확정하지 못해 주변 관계를 연결하지 않았습니다.')
        registration = context.get('registration')
        if registration:
            check(registration)
            self.add('콜백 등록', f"{registration['api']}의 {registration['event_type']} 이벤트 콜백 안에 있는 요청 구문", cp, indent='  ')
            self.plain_note(f"{registration['event_type']} 이벤트에 등록된 콜백 안의 요청 구문입니다.")
        binding = context.get('condition_binding')
        if binding:
            check(binding)
            self.add('조건의 대상 선택', f"{binding['identifier']}: 이벤트 대상에서 closest({binding['selector']})로 찾는 요소", cp, indent='  ')
            self.plain_note(f"조건의 {binding['identifier']}은 이벤트 대상에서 선택자 “{binding['selector']}”로 찾는 요소입니다.")
        controls = context.get('event_controls') or []
        if controls:
            for control in controls:
                check(control)
            self.add('같은 블록의 앞선 이벤트 제어 구문', ', '.join(v['api'] for v in controls), cp, indent='  ')
            self.plain_note('같은 블록에서 요청 구문 앞에 이벤트 동작을 제어하는 구문이 있습니다.')
        flow = context.get('response_flow')
        if flow:
            if flow.get('kind') != 'fetch_text_to_document_write':
                raise ValueError('javascript_request_response_flow_unsupported')
            writes = flow.get('writes')
            if (not isinstance(writes, list) or not all(isinstance(v, dict) for v in writes)
                    or [v.get('api') for v in writes] not in
                    [['document.write'], ['document.open', 'document.write', 'document.close']]
                    or not all(isinstance(flow.get(key), str) and flow[key] for key in ('read_parameter', 'write_parameter'))
                    or not isinstance(flow.get('read'), dict)
                    or flow['read'].get('api') != flow['read_parameter'] + '.text'):
                raise ValueError('javascript_request_response_flow_unsupported')
            check(flow['read'])
            for write in flow['writes']:
                check(write)
            chain = flow.get('chain_source_range')
            spans = [event['source_range'], flow['read']['source_range'],
                     *(v['source_range'] for v in flow['writes'])]
            if (not isinstance(chain, list) or len(chain) != 2 or not all(type(n) is int for n in chain)
                    or not 0 <= chain[0] < chain[1] <= len(source) or chain[0] != spans[0][0]
                    or any(not chain[0] <= lo < hi <= chain[1] for lo, hi in spans)
                    or any(a[1] > b[0] for a, b in zip(spans, spans[1:]))):
                raise ValueError('javascript_request_context_source_mismatch')
            self.add('응답 처리의 정적 연결', 'fetch → 첫 then에서 응답 text() 반환 → 다음 then의 매개변수를 document.write 인자로 사용', cp, indent='  ')
            self.plain_note('요청 결과를 텍스트로 읽고, 그 값을 다음 처리 함수에서 document.write에 전달하는 코드 연결이 있습니다.')
            self.add('문서 처리 구문', ' → '.join(v['api'] for v in flow['writes']), cp, indent='  ')
            self.note('실제 응답 내용·문서 변경 성공·자격정보 전송을 관측한 결과가 아님.', cp, indent='  ', public=True)
            self.plain_note('실제 응답 내용이나 문서 변경 성공을 확인한 결과는 아닙니다.')
        elif context.get('response_flow_unresolved'):
            self.add('응답 처리 연결', '후속 then 구문은 있으나 응답 값과 사용처의 연결은 미해석', cp, indent='  ')
            self.plain_note('후속 처리 구문은 있으나 응답 값이 어디에 사용되는지는 연결하지 못했습니다.')
        self.omit(cp['pointer'], 'raw and record retain exact ranges, source fragments and callback bindings; model selects recorded relationships and their limits')

    def reading_code(self, e, p):
        # Only a recorded link and matching source/call context share this quote.
        already_visible = any(e['script_id'] == sid and lo <= e['source_range'][0]
                              <= e['source_range'][1] <= hi for sid, lo, hi, _, _ in self.quote_spans)
        enclosing = [(i, request) for i, request in enumerate(self.js.get('network_requests') or [])
                     if request['script_id'] == e['script_id']
                     and request.get('call_context') == e.get('call_context')
                     and request['source_range'][0] <= e['source_range'][0] <= e['source_range'][1] <= request['source_range'][1]
                     and request['source_range'][1] - request['source_range'][0] <= self.text_chars
                     and any(link.get('source_event_id') == e.get('event_id') for link in request.get('source_links') or [])]
        if not already_visible and enclosing:
            i, request = min(enclosing, key=lambda pair: pair[1]['source_range'][1] - pair[1]['source_range'][0])
            rp = self.jp(f'/network_requests/{i}')
            self.add('함께 인용하는 범위', f'이 읽기를 포함하고 입력 연관이 기록된 요청 구문 {i + 1}', p, rp, indent='  ', public=False)
            self.code(request, rp)
            self.omit(p['pointer'] + '/source_excerpt', 'read source lies within the explicitly linked request quotation; read context and pointer retained')
        else:
            self.code(e, p)

    def code(self, e, p):
        sid, span = e['script_id'], e['source_range']
        source_index, script = self.scripts[sid]
        key = (sid, *span)
        if key in self.quoted:
            self.add('구문 인용', f'앞의 코드 인용 {self.quoted[key]}에 해당하는 원문 위치; 관측 문맥은 위에 별도 표시함.', p, indent='  ', public=False)
            self.omit(p['pointer'] + '/source_excerpt', 'same exact script and source range already quoted; occurrence and context retained', p['source'])
            return
        for known_sid, lo, hi, number, original_pointer in self.quote_spans:
            if sid == known_sid and lo <= span[0] <= span[1] <= hi:
                self.add('구문 인용', f'앞의 코드 인용 {number}의 원문 범위에 포함됨.', p, original_pointer, indent='  ', public=False)
                self.omit(p['pointer'] + '/source_excerpt', 'code already quoted in the enclosing recorded source range; occurrence and context retained', p['source'])
                return
        self.quoted[key] = len(self.quoted) + 1
        number = self.quoted[key]
        if span[1] - span[0] <= self.text_chars:
            ranges = [span]
        else:
            head = self.text_chars * 2 // 3
            ranges = [(span[0], span[0] + head), (span[1] - (self.text_chars-head), span[1])]
        self.quote_spans.extend((sid, lo, hi, number, p) for lo, hi in ranges)
        self.quote(f'코드 인용 {self.quoted[key]}', script['source'][span[0]:span[1]], p,
                   self.jp(f'/scripts/{source_index}/source'))

    def enclosing_branches(self, e):
        return [(i, b) for i, b in enumerate(self.js.get('branches') or [])
                if b is not e and b['script_id'] == e['script_id'] and b.get('call_context') == e.get('call_context')
                and b['source_range'] != e['source_range']
                and b['source_range'][0] <= e['source_range'][0] <= e['source_range'][1] <= b['source_range'][1]]

    def plain_note(self, text):
        if self.current_item and self.current_item.get('plain'):
            self.current_item['plain']['text'] += ' ' + text

    def context(self, e, p):
        for value in e.get('call_context') or []:
            match = re.fullmatch(r'(declaration|call)-(.+)-(\d+)-(\d+)', value)
            if not match or match[2] not in self.scripts:
                self.note('함수 문맥은 기록됐으나 원래 호출 위치를 해석하지 못함.', p, indent='  ')
                continue
            kind, sid, lo, hi = match[1], match[2], int(match[3]), int(match[4])
            i, script = self.scripts[sid]
            source = script.get('source')
            if not isinstance(source, str) or not 0 <= lo <= hi <= len(source):
                raise ValueError('javascript_call_context_source_range_invalid')
            if kind == 'declaration':
                self.plain_note('이 구문은 함수 선언의 본문에 있으며, 실제 함수 호출을 뜻하지 않습니다.')
                self.note('함수 선언 본문을 정적으로 살핀 발생; 이 문맥이 함수의 실제 호출을 뜻하지 않음.', p, indent='  ', public=True)
            else:
                self.quote('정적으로 연결된 함수 호출 구문', source[lo:hi], p, self.jp(f'/scripts/{i}/source'))
        control = e.get('control_context') or []
        enclosing = self.enclosing_branches(e)
        if not control and enclosing:
            i, _ = min(enclosing, key=lambda pair: pair[1]['source_range'][1] - pair[1]['source_range'][0])
            self.add('분기 내 위치', f'환경 분기 {i + 1}의 원문에 포함됨; 이 발생의 구체적인 갈래 조건은 별도 기록되지 않음.',
                     p, self.jp(f'/branches/{i}'), indent='  ')
        for depth, c in enumerate(control):
            construct, state = c.get('construct'), c.get('path_state')
            if construct == 'if':
                required = c.get('required_value')
                if c.get('condition'):
                    self.plain_note('조건 ' + ('일부 인용 ' if c.get('condition_truncated') else '') + '“' + c['condition'] + '”이 ' + ('참' if required is True else '거짓' if required is False else '기록된 조건값') + '인 갈래에 놓인 구문입니다.')
                    self.capture(['조건: ' + c['condition'] + (' — 참인 갈래' if required is True else ' — 거짓인 갈래' if required is False else '')], [p], (), public=True)
                branches = [(i, b) for i, b in enclosing if b.get('condition') == c.get('condition')
                            and b.get('control_context', []) == control[:depth]]
                if len(branches) == 1:
                    i, _ = branches[0]
                    self.add('조건 문맥', f'환경 분기 {i + 1}의 ' + ('참인 갈래' if required is True else '거짓인 갈래' if required is False else '조건값 미기록 갈래'),
                             p, self.jp(f'/branches/{i}'), indent='  ', public=False)
                else:
                    self.add('둘러싼 조건', c.get('condition') or '조건 원문 미기록', p, indent='  ')
                    self.add('해당 갈래', '조건이 참인 갈래' if required is True else '조건이 거짓인 갈래' if required is False else '조건값 미기록', p, indent='  ')
                if state == 'literal_excludes_arm':
                    self.plain_note('기록된 고정 조건값은 이 갈래의 진입 조건과 맞지 않습니다.')
                    self.note('기록된 리터럴 조건은 이 갈래의 진입 조건과 맞지 않음.', p, indent='  ', public=True)
                elif state == 'literal_allows_arm':
                    self.note('기록된 리터럴 조건은 이 갈래와 맞음; 실제 실행을 관측한 결과는 아님.', p, indent='  ', public=True)
                elif not branches:
                    self.note('실제로 이 갈래가 선택되는지는 미관측.', p, indent='  ')
            elif construct == 'preceding_block_exit':
                statement = {'ReturnStatement': 'return', 'ThrowStatement': 'throw', 'BreakStatement': 'break', 'ContinueStatement': 'continue'}.get(c.get('statement'), '종료 구문')
                self.add('정적 위치', f'같은 블록의 {statement} 뒤에 놓인 구문', p, indent='  ')
                self.plain_note('같은 코드 블록의 흐름을 종료하거나 바꾸는 구문 뒤에 놓여 있습니다.')
            elif construct in {'WhileStatement', 'DoWhileStatement', 'ForStatement', 'ForInStatement', 'ForOfStatement'}:
                self.add('반복 구문 조건', c.get('condition') or '별도 조건 원문 미기록', p, indent='  ')
                self.plain_note('반복 구문 안에 있으며' + (' 조건은 “' + c['condition'] + '”입니다.' if c.get('condition') else ' 별도 조건은 기록돼 있지 않습니다.'))
                if state == 'literal_excludes_body':
                    self.plain_note('기록된 고정 조건값은 반복 본문에 들어가는 것을 제외합니다.')
                self.note('기록된 리터럴 조건이 반복 본문 진입을 제외함.' if state == 'literal_excludes_body'
                          else '반복 횟수와 실제 반복 경로는 미해석.', p, indent='  ', public=state == 'literal_excludes_body')
            else:
                self.note('추가 제어 문맥이 기록됐으나 이 본문에서 의미를 해석하지 않음.', p, indent='  ')
            if c.get('condition_truncated'):
                self.note('위 조건은 생산자가 일부만 기록한 인용임.', p, indent='  ')

    def scope(self):
        self.start('JavaScript 관측 범위')
        url = self.analysis.get('document_url') or (self.record.get('target') or {}).get('document_url')
        if url:
            self.add('문서', url, self.jp('/analysis'))
        self.note('제공된 스크립트의 정적 구조와 분석기가 기록한 관계를 정리함. 코드·생성 함수·네트워크 요청·페이지 이동을 실행한 결과가 아님.',
                  pointer('/scope', 'selection'))
        self.note('분석기는 모든 JavaScript 연산 의미와 제어 흐름을 해석하지 않음. 문맥이 비어 있거나 관련 관측이 없어도 실행 가능성·부재를 확정하지 않음.',
                  pointer('/semantic_scope', 'selection'))
        if not self.scripts:
            doc = self.html.get('document') or {}
            if doc.get('source_available') is False:
                message = 'HTML 원문을 확보하지 못했고 별도 스크립트도 제공되지 않음; 페이지의 JavaScript 부재를 확인한 결과가 아님.'
            elif doc.get('parse_succeeded') is False:
                message = 'HTML 구조를 파싱하지 못했고 별도 스크립트도 제공되지 않아 스크립트 범위를 확인할 수 없음.'
            elif doc.get('source_complete') is False:
                message = '일부 HTML 범위에서 스크립트가 제공되지 않음; 나머지 영역은 미확인.'
            else:
                message = '제공된 자료에 script 분석 항목이 없음; 페이지 실행 전체의 동작 부재를 뜻하지 않음.'
            self.note(message, self.jp('/scripts'), pointer('/html/document'))
        for sid, (i, s) in self.scripts.items():
            p = self.jp(f'/scripts/{i}')
            label = '인라인 스크립트로 제공됨' if s.get('type') == 'inline' else '외부 스크립트' if s.get('type') == 'external' else '종류 미해석 스크립트'
            self.add(f'스크립트 {i + 1}', label, p)
            if s.get('source_url'):
                self.add('기록된 소스 주소', s['source_url'], p, indent='  ')
            state = s.get('analysis_status')
            text = STATUS.get(state, '분석 상태 미기록 또는 미해석')
            if state == 'parsed' and s.get('source') == '':
                text = '확보한 빈 원문을 구문 분석함'
            self.add('자료 상태', text, p, indent='  ')
            state_cause = {
                'missing_source': 'javascript_source_unavailable',
                'source_limit_exceeded': 'javascript_source_limit_exceeded',
                'parser_unavailable': 'javascript_parser_unavailable',
            }.get(state)
            if state_cause:
                for cause_index, cause in enumerate(self.record.get('causes') or []):
                    detail = cause.get('detail') or {}
                    if (cause.get('code') == state_cause and detail.get('script_id') == sid
                            and detail.get('message') == STANDARD_MESSAGES[state_cause]):
                        self.line_map[-1]['sources'].append(pointer(f'/causes/{cause_index}', 'record'))
                        self.ids.append(cause['id'])
                        self.used_causes.add(cause['id'])
                        self.omit(f'/causes/{cause_index}/detail/message', 'same occurrence and known producer template already expressed in the script acquisition state', 'record')
            if state == 'data_block':
                self.add('선언된 종류', s.get('media_type') or '미기록', p, indent='  ')
            if s.get('truncated'):
                self.note('원문 일부만 확보됨; 아래 관측은 확보한 부분의 결과임.', p, indent='  ')
            attrs = [label for key, label in [('async_script', 'async'), ('defer_script', 'defer')] if s.get(key)]
            if s.get('media_type') == 'module':
                attrs.append('module')
            if attrs:
                self.add('실행 방식 선언', ', '.join(attrs) + '; 스크립트 간 연결·실제 실행 순서는 미확인', p, indent='  ')
                for cause_index, cause in enumerate(self.record.get('causes') or []):
                    detail = cause.get('detail') or {}
                    if (cause.get('code') == 'script_order_unresolved' and detail.get('script_id') == sid
                            and detail.get('message') == STANDARD_MESSAGES['script_order_unresolved']):
                        self.line_map[-1]['sources'].append(pointer(f'/causes/{cause_index}', 'record'))
                        self.ids.append(cause['id'])
                        self.used_causes.add(cause['id'])
                        self.omit(f'/causes/{cause_index}/detail/message', 'same script order limitation occurrence already stated with async/defer/module declaration', 'record')
            response = s.get('response') or {}
            if response.get('status_code') is not None and state != 'parsed':
                self.add('수집 응답 상태', response['status_code'], p, indent='  ')
            self.omit(p['pointer'] + '/source', 'full source retained; only relationship-bound code ranges selected')
        missing = [key for key in POLICIES if self.analysis.get(key) is False]
        if missing:
            sources = [self.jp('/analysis/' + k) for k in missing]
            for i, cause in enumerate(self.record.get('causes') or []):
                if cause.get('code') == 'detection_policy_unresolved' and set((cause.get('occurrence') or {}).get('affected_signal_ids', [])) & set(JS_IDS):
                    sources.append(pointer(f'/causes/{i}', 'record'))
                    self.used_causes.add(cause['id'])
            self.add('미설정된 분석 기준', ', '.join(POLICIES[k] for k in missing), *sources)
        if self.html.get('inline_handlers'):
            self.note('HTML 이벤트 속성의 코드 원문은 별도 HTML 선언으로 보존됨. 이 스크립트 분석 결과와 같은 요소·호출로 연결된 자료는 없음.',
                      pointer('/html/inline_handlers'))
        if any(s.get('analysis_status') == 'parsed' for _, s in self.scripts.values()) and not self.reads and not any(self.js.get(k) for k in EVENTS):
            self.note('지원된 분석에서 이 본문에 표시할 정적 동작이 기록되지 않음. 지원 밖 표현식이나 실제 실행의 부재를 확정한 결과는 아님.',
                      self.jp('/analysis'))
        self.finish()

    def select_content_rows(self, rows):
        """Keep declared text/target relationships, not configuration labels."""
        groups = {}
        for row in rows:
            groups.setdefault(row[0].rsplit('/', 1)[0], []).append(row)
        doc_url = self.analysis.get('document_url') or (self.record.get('target') or {}).get('document_url')
        def host(url):
            try:
                parsed = urlsplit(url or '')
                return parsed.hostname if parsed.scheme in {'http', 'https'} else None
            except ValueError:
                return None
        doc_host = host(doc_url)
        known_navigation = bool(doc_host) and any(
            host(link.get('destination_url')) == doc_host for link in self.html.get('links') or [])
        chosen, content_arrays = set(), set()
        for group_path, values in groups.items():
            texts = [r for r in values if r[1] == 'text']
            addresses = [r for r in values if r[1] == 'address']
            if not texts or not addresses:
                continue
            # A menu configuration is not an observed input/submit/continue
            # control. Keep concrete controls and unknown/different targets.
            control = any(str(r[4]).casefold() in {'button', 'submit', 'form', 'input', 'cta', 'action'}
                          or re.sub(r'[^a-z]', '', r[0].rsplit('/', 1)[-1].casefold()) in {'text', 'buttontext', 'action', 'actionurl', 'targeturl'}
                          for r in values)
            menu = bool(re.search(r'(?:^|/)[^/]*(?:menu|nav)[^/]*(?:/|$)', group_path, re.I))
            repeated_navigation = (menu and not control and known_navigation
                                   and all(host(r[3]) is not None and host(r[3]) == doc_host for r in addresses))
            if repeated_navigation:
                continue
            chosen.add(group_path)
            if control and re.search(r'/\d+$', group_path):
                content_arrays.add(group_path.rsplit('/', 1)[0])
        for group_path, values in groups.items():
            if (re.search(r'/\d+$', group_path)
                    and group_path.rsplit('/', 1)[0] in content_arrays
                    and any(str(r[4]).casefold() in {'title', 'heading', 'text', 'paragraph', 'image', 'video', 'audio'}
                            for r in values)):
                chosen.add(group_path)
        return [r for r in rows if r[0].rsplit('/', 1)[0] in chosen]

    def content_data(self):
        """Select related content fields from a producer-recorded declaration.

        Paths keep separate array elements/objects apart. A literal URL is a
        data declaration; it is not promoted to a navigation or network event.
        """
        declarations = self.js.get('static_data') or []
        if not declarations:
            return
        matches = [(i, fact) for i, fact in enumerate(self.record.get('analysis_facts') or [])
                   if fact.get('kind') == 'static_literal_content_data']
        if len(matches) != 1 or canonical(matches[0][1].get('declarations')) != canonical(declarations):
            raise ValueError('javascript_static_data_record_source_mismatch')
        fact_index, fact = matches[0]
        fields = fact.get('content_fields')
        if not isinstance(fields, list) or len(fields) != len(declarations):
            raise ValueError('javascript_static_data_fields_missing')

        self.start('코드에 선언된 콘텐츠 데이터')
        for index, declaration in enumerate(declarations):
            self.validate_event(declaration)
            rows = []
            for entry in fields[index]:
                value = declaration['value']
                for token in entry['path'].lstrip('/').split('/'):
                    token = token.replace('~1', '/').replace('~0', '~')
                    value = value[int(token)] if isinstance(value, list) else value[token]
                if value != entry['value'] or entry['kind'] not in {'text', 'address', 'resource'}:
                    raise ValueError('javascript_static_content_field_source_mismatch')
                rows.append((entry['path'], entry['kind'], entry['value'], entry['resolved_url'], entry.get('declared_type')))
            total_rows = len(rows)
            rows = self.select_content_rows(rows)
            if len(rows) != total_rows:
                self.omit(f'/javascript/static_data/{index}',
                          'literal configuration labels without a text/address relationship, or same-host menu catalogue repeating the observed navigation relation; complete declaration retained',
                          selected_count=len(rows), total_count=total_rows)
            if not rows:
                if total_rows == 0:
                    self.omit(f'/javascript/static_data/{index}', 'literal configuration without selected content text; source and complete declaration retained')
                continue
            p = self.jp(f'/static_data/{index}')
            rp = pointer(f'/analysis_facts/{fact_index}/declarations/{index}', 'record')
            label = f'콘텐츠 데이터 {index + 1}'
            brief = []
            for _, kind, value, _, _ in rows:
                if kind == 'resource':
                    continue
                shown = value if len(value) <= 400 else value[:300] + ' … ' + value[-100:]
                brief.append(('문구 ' if kind == 'text' else '주소 ') + shown)
                if len(brief) == 8:
                    break
            self.begin_item(label, basis='static_relation', plain={
                'title': '페이지 코드에 함께 적힌 문구와 주소',
                'text': '코드의 같은 콘텐츠 데이터에 ' + ' / '.join(brief) + '가 적혀 있습니다. 실제 표시나 클릭 결과를 확인한 내용은 아닙니다.'})
            self.add(label, self.location(declaration), p, rp)
            self.add('데이터를 대입하는 이름', declaration.get('assignment_target'), p, public=False)
            self.note('아래 경로는 같은 선언 안의 객체·배열 위치다. 서로 다른 항목을 같은 버튼이나 제출 경로로 합치지 않음.', p)
            shown_types = set()
            for path, kind, value, url, declared_type in rows[:60]:
                object_path = path.rsplit('/', 1)[0] or '/'
                if declared_type is not None and object_path not in shown_types:
                    self.add('데이터 항목 ' + object_path + '의 type 선언', declared_type, p, rp, indent='  ')
                    shown_types.add(object_path)
                name = {'text': '문구 선언', 'address': '주소 선언', 'resource': '리소스 주소 선언'}[kind]
                self.quote(name + ' ' + path, value, p, rp)
                if url is not None and url != value:
                    self.add('문서 주소를 기준으로 해석한 주소', url, p, rp, indent='  ')
                elif url is None and kind in {'address', 'resource'}:
                    self.note('이 선언은 HTTP(S) 주소로 해석하지 못함.', p)
            if len(rows) > 60:
                self.note('콘텐츠 데이터의 추가 항목은 이 본문에서 생략함; 전체 선언은 내부 자료에 보존됨.', p)
                self.omit(p['pointer'], 'bounded content field selection; complete literal declaration retained', selected_count=60, total_count=len(rows))
            self.end_item()
        if self.lines:
            self.note('콘텐츠 데이터의 문구·주소는 코드에 적힌 값이며, 화면 표시·클릭·도착지 응답·정보 전송을 관측한 결과가 아님.', self.jp('/static_data'))
        self.finish()

    def execution(self):
        self.start('문자열 변환과 동적 API 사용')
        for i, e in enumerate(self.js.get('dynamic_execution') or []):
            e, p = self.event('dynamic_execution', i, f'동적 API 구문 {i + 1}', ('L3-J-01',))
            api = e.get('api') or 'API 미기록'
            if api == 'Function':
                self.add('기록된 API', 'Function — 문자열로 함수를 만드는 구문; 생성된 함수의 실행은 미확인', p, indent='  ')
            else:
                self.add('기록된 API', api, p, indent='  ')
            if e.get('invocation') == 'constructor':
                self.note('new를 사용한 생성 구문으로 기록됨.', p, indent='  ')
            for link in e.get('decode_links') or []:
                found = self.resolve('decode_operations', link.get('event_id'))
                if found is None:
                    self.add('문자열 변환 연결', (link.get('method') or '방법 미기록') + '; 참조한 원래 변환 발생이 없거나 모호하여 연결 범위 미확인', p, ids=('L3-J-02',), indent='  ')
                    continue
                j, original = found
                if link.get('method') is not None and link['method'] != original.get('method'):
                    raise ValueError('javascript_decode_link_method_mismatch')
                self.decode_used.add(j)
                self.add('기록된 입력 계보', (link.get('method') or original.get('method') or '변환') + ' → 위 API의 첫 번째 인자',
                         p, self.jp(f'/decode_operations/{j}'), ids=('L3-J-02',), indent='  ')
                self.code(original, self.jp(f'/decode_operations/{j}'))
            for ref in e.get('input_links') or []:
                found = self.resolve('credential_access', ref)
                self.add('기록된 입력 읽기 연결', self.credential_labels.get(ref, '참조한 원래 읽기 발생이 없거나 모호함') if found else '참조한 원래 읽기 발생이 없거나 모호함',
                         p, *([self.read_sources[found[0]]] if found else []), indent='  ')
            if api == 'Function' and e.get('decode_links'):
                self.note('위 계보는 생산자가 기록한 첫 번째 인자 기준임. 해당 인자가 생성 함수의 본문인지까지 확인한 결과는 아님.', p, indent='  ')
        for i, e in enumerate(self.js.get('decode_operations') or []):
            if i not in self.decode_used:
                e, p = self.event('decode_operations', i, f'별도 문자열 변환 {i + 1}', ('L3-J-02',))
                self.add('기록된 방법', e.get('method') or '미기록', p, indent='  ')
                self.note('동적 API 입력으로 이어지는 계보는 이 관측 목록에 기록되지 않음.', p, indent='  ')
        self.finish()
        self.start('스크립트 생성·삽입 구조')
        for i, e in enumerate(self.js.get('script_injection') or []):
            e, p = self.event('script_injection', i, f'스크립트 삽입 {i + 1}', ('L3-J-03',))
            self.add('삽입 API', e.get('api') or '미기록', p, indent='  ')
            self.add('기록된 소스 주소', e.get('url') or '해석된 주소가 기록되지 않음', p, indent='  ')
        if self.lines:
            self.note('생성한 script 요소의 삽입 구조이며, 해당 소스의 다운로드·내용·실행은 관측하지 않음.', self.jp('/script_injection'))
        self.finish()

    def input_description(self, e):
        matches = [(i, f) for i, f in enumerate(self.html.get('inputs') or []) if f.get('field_id') == e.get('field_id')]
        kind = CREDENTIALS.get(e.get('credential_type'), e.get('credential_type') or '미기록')
        if len(matches) != 1:
            return kind + ' 종류로 분류된 입력; HTML 요소 대응이 미확정', []
        i, f = matches[0]
        attributes = [('HTML id', f.get('html_id')), ('name', f.get('name'))]
        label = ', '.join(f'{key}={value}' for key, value in attributes if value)
        return kind + ' 종류로 분류된 HTML 입력' + (' (' + label + ')' if label else ''), [pointer(f'/html/inputs/{i}')]

    def destination(self, e, p, index):
        url = e.get('destination_url')
        key = canonical({k: e.get(k) for k in ('destination_url', 'destination_prefix',
                         'destination_candidates', 'relations', 'external')})
        if url and key in self.destinations_seen:
            first, original_pointer = self.destinations_seen[key]
            self.add('요청 대상', f'요청 구문 {first + 1}과 같은 주소·사이트 관계로 기록됨.', p, original_pointer, indent='  ')
            return
        if url:
            self.destinations_seen[key] = (index, p)
        if url:
            self.add('해석된 요청 대상', url, p, indent='  ')
        elif e.get('destination_prefix'):
            self.add('정적으로 확인된 주소 앞부분', e['destination_prefix'], p, indent='  ')
            self.note('전체 요청 주소는 미확정.', p, indent='  ')
        else:
            self.note('요청 대상 주소는 미해석.', p, indent='  ')
        candidates = e.get('destination_candidates') or []
        for value in unique(v for v in candidates if v and v != url):
            self.add('선택이 확정되지 않은 주소 후보', value, p, indent='  ')
        if any(v is None for v in candidates):
            self.note('주소로 해석하지 못한 후보도 기록됨.', p, indent='  ')
        r = e.get('relations') or {}
        if r.get('same_origin') is True:
            self.note('문서와 같은 오리진으로 기록됨.', p, indent='  ', public=True)
        elif r.get('same_site_scope') is True:
            self.note('문서와 같은 사이트 범위로 기록됨; ' + (
                '오리진(프로토콜·호스트·포트)은 다름.' if r.get('same_origin') is False else '오리진 관계는 미확정.'),
                p, indent='  ', public=True)
        elif r.get('same_site_scope') is False:
            self.note('문서와 다른 사이트 범위로 기록됨.', p, indent='  ', public=True)
            if r.get('same_icann_domain') is True:
                self.note('ICANN 등록 도메인은 같지만 private suffix를 반영한 사이트 범위는 다름.', p, indent='  ', public=True)
        elif e.get('external') is not None:
            self.note('생산 결과의 외부 목적지 표시는 있으나 상세 주소 관계는 미기록.', p, indent='  ')
        else:
            self.note('문서와 목적지의 사이트 범위 관계는 미확정.', p, indent='  ')

    @staticmethod
    def request_labels(indices):
        ranges = []
        for index in sorted(indices):
            number = index + 1
            if ranges and ranges[-1][1] + 1 == number:
                ranges[-1][1] = number
            else:
                ranges.append([number, number])
        return '요청 구문 ' + ', '.join(str(lo) if lo == hi else f'{lo}~{hi}' for lo, hi in ranges)

    def inputs_network(self):
        self.start('입력 읽기와 요청 인자 관계')
        configured = {
            'invalid_get_head_body': 'GET/HEAD와 비어 있지 않은 본문이 충돌하는 설정으로 기록됨; 전달 관계를 확정하지 않음',
            'body_nullability_unresolved': 'GET/HEAD 본문의 null 여부가 미확정',
            'method_unresolved': '요청 방식이 미해석되어 설정의 유효성이 미확정',
            'not_checked': '요청 방식·본문·옵션 조합 유효성은 검사하지 않음',
        }
        if any(e.get('source_links') or e.get('unresolved_source_links') for e in self.js.get('network_requests') or []):
            self.note('입력 연관은 제한된 정적 계보 분석 결과임. 식의 모든 연산 의미·실제 입력값·전달 값·요청 성공이나 유출을 확인한 결과가 아님.',
                      pointer('/dataflow_scope', 'selection'))
        # Share equal technical states, never infer a shared cause or merge events.
        config_groups, no_link_groups = {}, {}
        for i, e in enumerate(self.js.get('network_requests') or []):
            api, configuration = e.get('api') or 'API 미기록', e.get('request_configuration')
            if configuration in configured:
                config_groups.setdefault((api, configuration), []).append(i)
            if not e.get('source_links') and not e.get('unresolved_source_links') and self.reads:
                no_link_groups.setdefault(api, []).append(i)
        shared_configuration, shared_no_link = set(), set()
        for (api, configuration), indices in config_groups.items():
            if len(indices) < 2:
                continue
            self.add(self.request_labels(indices) + '의 공통 요청 설정 한계',
                     api + ' — ' + configured[configuration],
                     *(self.jp(f'/network_requests/{i}') for i in indices))
            shared_configuration.update(indices)
            for i in indices:
                self.omit(f'/javascript/network_requests/{i}/request_configuration',
                          'same API and recorded configuration state shared in a request-numbered row; every occurrence and pointer retained')
        for api, indices in no_link_groups.items():
            if len(indices) < 2:
                continue
            self.add(self.request_labels(indices) + '의 입력 연결 범위',
                     api + ' — 별도로 기록된 입력 읽기가 이 요청들의 인자로 연결됐다는 분석 결과는 없음.',
                     *(self.jp(f'/network_requests/{i}') for i in indices))
            shared_no_link.update(indices)
            for i in indices:
                self.omit(f'/javascript/network_requests/{i}/source_links',
                          'empty preserved and unresolved link lists share one scoped absence statement; requests remain distinct')
        for i, e in enumerate(self.reads):
            e, p = self.event('credential_access', i, f'입력 읽기 {i + 1}', ('L3-J-05',))
            description, sources = self.input_description(e)
            self.add('읽기 대상', description, p, *sources, indent='  ')
        for i, e in enumerate(self.js.get('network_requests') or []):
            e, p = self.event('network_requests', i, f'요청 구문 {i + 1}', ('L3-J-04', 'L3-J-06'))
            self.add('요청 API', e.get('api') or '미기록', p, indent='  ')
            self.destination(e, p, i)
            configuration = e.get('request_configuration')
            if configuration in configured and i not in shared_configuration:
                self.add('요청 설정 한계', configured[configuration], p, indent='  ', public=False)
            for j, link in enumerate(e.get('source_links') or []):
                found = self.resolve('credential_access', link.get('source_event_id'))
                lp = self.jp(f'/network_requests/{i}/source_links/{j}')
                if found is None:
                    self.note('입력 연관은 기록됐으나 참조한 읽기 발생이 없거나 모호하여 연결 범위를 확인할 수 없음.', lp, indent='  ')
                    continue
                if any(link.get(key) != found[1].get(key) for key in ('field_id', 'credential_type')):
                    raise ValueError('javascript_source_link_identity_mismatch')
                route = [self.credential_labels[link['source_event_id']], *link.get('transformations', []),
                         POSITIONS.get(link.get('transmission_position'), '전달 위치 미해석')]
                self.add('분석기가 기록한 입력 연관', ' → '.join(route), lp, self.read_sources[found[0]], indent='  ')
                self.plain_note('분석기가 입력값 읽기와 이 요청 인자 사이의 정적 연결을 기록했습니다. 실제 전달된 값이나 요청 성공을 확인한 결과는 아닙니다.')
            if e.get('source_links'):
                relevant_scripts = {e['script_id']}
                relevant_scripts.update(self.resolve('credential_access', link.get('source_event_id'))[1]['script_id']
                                        for link in e['source_links'] if self.resolve('credential_access', link.get('source_event_id')))
                for cause_index, cause in enumerate(self.record.get('causes') or []):
                    sid = (cause.get('detail') or {}).get('script_id')
                    if (cause.get('code') == 'conditional_value_unresolved' and sid in relevant_scripts
                            and cause['id'] not in self.used_causes):
                        cp = pointer(f'/causes/{cause_index}', 'record')
                        self.add('스크립트 단위의 값 해석 한계',
                                 f'스크립트 {self.scripts[sid][0] + 1}에는 조건에 따라 값이 달라져 최종 값을 확정하지 못한 부분이 기록됨.',
                                 p, cp, ids=(cause['id'],), indent='  ', public=False)
                        self.note('이 한계를 위 요청의 특정 인자 계산과 직접 연결한 자료는 없음.', cp, indent='  ')
                        self.render_cause_detail(cause, cause_index)
                        self.used_causes.add(cause['id'])
            if (not e.get('source_links') and not e.get('unresolved_source_links')
                    and self.reads and i not in shared_no_link):
                self.note('별도로 기록된 입력 읽기가 이 요청 인자로 연결됐다는 분석 결과는 없음.', p, indent='  ')
            if e.get('unresolved_source_links'):
                self.note('분석 결과 제한으로 원래 읽기 발생을 함께 보존하지 못한 연결이 있음; 완전한 연결로 재구성하지 않음.', p, indent='  ')
        self.finish()

    @staticmethod
    def branch_value(value):
        if isinstance(value, dict) and 'type' in value:
            kind = {
                'Identifier': '변수 식; 이름·값 미기록',
                'ObjectExpression': '객체 식; 내부 구성·값 미기록',
                'ArrayExpression': '배열 식; 원소·값 미기록',
                'MemberExpression': '속성 접근 식; 대상·값 미기록',
                'CallExpression': '호출 식; 결과 값 미해석',
                'NewExpression': '생성 식; 결과 값 미해석',
                'ConditionalExpression': '조건 식; 선택·값 미해석',
                'UnaryExpression': '단항 연산 식; 결과 값 미해석',
                'BinaryExpression': '이항 연산 식; 결과 값 미해석',
                'LogicalExpression': '논리 연산 식; 결과 값 미해석',
                'AssignmentExpression': '대입 식; 값 미해석',
                'TemplateLiteral': '문자열 조합 식; 결과 값 미해석',
            }.get(value['type'], '일부만 구조화된 식; 세부 값 미기록')
            return '(' + kind + ')'
        return json.dumps(value, ensure_ascii=False, default=str)

    def branch_supplement(self, e, index):
        if e['source_range'][1] - e['source_range'][0] <= self.text_chars:
            return
        p = self.jp(f'/branches/{index}')
        self.note('분기 원문에 생략 구간이 있어, 생산자가 별도로 기록한 갈래별 구문을 보충함. 식의 일부는 종류만 기록되어 있음.', p, indent='  ')
        for arm_index, arm in enumerate(e.get('branches') or []):
            label = '참인 갈래' if arm.get('condition_result') is True else '거짓인 갈래' if arm.get('condition_result') is False else '조건값 미기록 갈래'
            ap = self.jp(f'/branches/{index}/branches/{arm_index}')
            if not arm.get('observations'):
                self.add(label, '구조화된 호출·대입·종료 구문이 기록되지 않음; 전체 동작의 부재를 뜻하지 않음', ap, indent='  ')
            for observation_index, observation in enumerate(arm.get('observations') or []):
                op = self.jp(f'/branches/{index}/branches/{arm_index}/observations/{observation_index}')
                target, kind = observation.get('target') or '대상 미기록', observation.get('kind')
                if kind == 'call':
                    args = observation.get('arguments') or []
                    value = f'호출·생성 대상 {target}; ' + ('인자: ' + ', '.join(self.branch_value(v) for v in args) if args else '인자 없음')
                elif kind == 'assignment':
                    value = f'대입 대상 {target}; 기록된 값: ' + self.branch_value(observation.get('value'))
                elif kind in {'return', 'throw'}:
                    value = kind + ' 구문; 대상 값과 실행 경로는 이 구조 요약에서 미기록'
                else:
                    value = '구조화된 구문은 있으나 본문에서 해석을 지원하지 않는 종류임'
                self.quote(label + '의 기록된 구문', value, op, source_text=False)

    def navigation_environment(self):
        self.start('페이지 이동과 환경 조건')
        comparisons = self.evidence('L3-J-09').get('branch_comparisons') or []
        covered_environment = set()
        for i, e in enumerate(self.js.get('branches') or []):
            e, p = self.event('branches', i, f'환경 분기 {i + 1}', ('L3-J-08', 'L3-J-09'))
            sources = [p]
            for j, env in enumerate(self.js.get('environment_access') or []):
                if (env['script_id'] == e['script_id'] and env.get('call_context') == e.get('call_context')
                        and env.get('control_context') == e.get('control_context')
                        and e['source_range'][0] <= env['source_range'][0] <= env['source_range'][1] <= e['source_range'][1]
                        and env.get('source_excerpt') == e.get('condition')
                        and self.scripts[e['script_id']][1]['source'][e['source_range'][0]:e['source_range'][1]].count(e.get('condition') or '\0') == 1
                        and env.get('property') in (e.get('properties') or [])):
                    covered_environment.add(j)
                    sources.append(self.jp(f'/environment_access/{j}'))
            self.add('기록된 조건', e.get('condition') or '미기록', *sources, indent='  ')
            match = [c for c in comparisons if c.get('event') == e]
            if match:
                self.note('설정된 정책이 정규화한 두 갈래 표현에서 차이를 기록함. 실제 경로 선택이나 모든 코드 차이를 비교한 결과는 아님.',
                          p, self.rp('L3-J-09', '/evidence/branch_comparisons'), indent='  ')
            else:
                self.note('두 갈래의 원문 구조를 보존함. 정책의 차이 선택 여부만으로 두 갈래의 전체 동작이 같다고 해석할 수 없음.', p, indent='  ')
            self.branch_supplement(e, i)
        for i, e in enumerate(self.js.get('redirects') or []):
            e, p = self.event('redirects', i, f'이동 구문 {i + 1}', ('L3-J-07',))
            self.add('이동 API 또는 대입 대상', e.get('api') or '미기록', p, indent='  ')
            self.add('해석된 이동 대상', e.get('destination_url') or '대상 주소 미해석', p, indent='  ')
        for i, e in enumerate(self.js.get('environment_access') or []):
            if i in covered_environment:
                self.omit(f'/javascript/environment_access/{i}', 'environment read lies in the recorded branch source; pointer retained with branch condition')
                continue
            e, p = self.event('environment_access', i, f'환경 속성 읽기 {i + 1}', ('L3-J-08',))
            self.add('기록된 속성', e.get('property') or '미기록', p, indent='  ')
        if self.lines:
            self.note('이동 성공·도착 페이지·환경값·분기 선택은 미관측. 환경 속성을 읽었다는 사실만으로 탐지 회피 의도를 확정하지 않음.',
                      self.jp('/redirects'), self.jp('/branches'), self.jp('/environment_access'))
        self.finish()

    def render_cause_detail(self, cause, index):
        self.end_item()
        detail, code = cause.get('detail') or {}, cause.get('code')
        p = pointer(f'/causes/{index}', 'record')
        sid = detail.get('script_id') or ((cause.get('occurrence') or {}).get('observed_target') or {}).get('script_id')
        message = detail.get('message')
        if message and code in LIMITS and message != STANDARD_MESSAGES.get(code):
            self.add('기록된 상세 이유', message, p, indent='  ')
        elif message and message == STANDARD_MESSAGES.get(code):
            self.omit(p['pointer'] + '/detail/message', 'known producer template already expressed in the nearby Korean limitation', 'record')
        if detail.get('source_excerpt'):
            if sid in self.scripts and detail.get('source_range') is not None:
                located = {**detail, 'script_id': sid}
                self.validate_source(located)
                self.code(located, pointer(p['pointer'] + '/detail', 'record'))
            else:
                self.quote('생산자가 기록한 구문 인용', detail['source_excerpt'], p)
                self.note('전체 원문 범위와의 대응이 기록되지 않아 인용의 완전성은 미확인.', p, indent='  ')
        if detail.get('url') and (sid not in self.scripts or detail['url'] != self.scripts[sid][1].get('source_url')):
            self.add('한계 대상 주소', detail['url'], p, indent='  ')
        if not message and code in WRAPPERS:
            self.note('개별 사유가 없으면 다른 스크립트의 실패 원인을 이 결과에 대신 적용하지 않음.', p, indent='  ')

    def limits(self):
        self.start('JavaScript 관측·해석 한계')
        for i, cause in enumerate(self.record.get('causes') or []):
            if cause['id'] in self.used_causes:
                continue
            detail, occurrence = cause.get('detail') or {}, cause.get('occurrence') or {}
            affected = set(occurrence.get('affected_signal_ids') or [])
            code = cause.get('code')
            relevant = bool(affected & set(JS_IDS)) or occurrence.get('stage') in {'javascript_analysis', 'script_collection', 'script_decoding'} or bool(detail.get('script_id'))
            if not relevant:
                continue
            p = pointer(f'/causes/{i}', 'record')
            if code in WRAPPERS and detail.get('causes'):
                self.omit(p['pointer'], 'propagated analysis wrapper; individual recorded causes shown', 'record')
                continue
            sid = detail.get('script_id') or (occurrence.get('observed_target') or {}).get('script_id')
            label = f'스크립트 {self.scripts[sid][0] + 1} 한계' if sid in self.scripts else '분석 한계'
            text = LIMITS.get(code, detail.get('message') or detail.get('error') or code or '이유 미기록')
            sources = [p]
            if code == 'credential_classification_failed':
                target = detail.get('target') or (occurrence.get('observed_target') or {}).get('target') or {}
                matches = [(j, field) for j, field in enumerate(self.html.get('inputs') or [])
                           if field.get('field_id') == target.get('field_id')
                           and (target.get('field_index') is None or target['field_index'] == j)]
                if len(matches) == 1:
                    j, field = matches[0]
                    attributes = ', '.join(f'{name}={value}' for name, value in [
                        ('HTML id', field.get('html_id')), ('name', field.get('name'))] if value)
                    label = f'HTML 입력 {j + 1} 분류 한계'
                    text = '이 입력의 인증 종류 분류에 실패함' + (f' ({attributes})' if attributes else '')
                    sources.append(pointer(f'/html/inputs/{j}'))
                else:
                    text += '; 해당 HTML 입력과의 대응이 미확정'
            self.add(label, text, *sources, ids=(cause['id'],))
            self.render_cause_detail(cause, i)
        explained_source_limit = any(s.get('truncated') or s.get('analysis_status') in {
            'missing_source', 'source_limit_exceeded', 'parser_unavailable', 'parse_error'
        } for _, s in self.scripts.values())
        if self.analysis.get('source_complete') is False and not self.lines and not explained_source_limit:
            self.note('전체 소스 분석 범위가 불완전하다고 기록됨; 개별 추가 사유는 미기록.', self.jp('/analysis/source_complete'))
        if self.analysis.get('semantic_complete') is False and not self.lines and not explained_source_limit and not self.used_causes:
            self.note('정적 관계 해석에 한계가 기록됨; 개별 추가 사유는 미기록.', self.jp('/analysis/semantic_complete'))
        self.finish()

    def build(self):
        self.scope()
        self.content_data()
        self.navigation_environment()
        self.execution()
        self.inputs_network()
        self.limits()
        for sid, (i, _) in self.signals.items():
            self.omit(f'/signals/{i}', 'signal booleans, inventories, counts, representatives and serialized normalization remain internal; recorded relationships selected instead', 'record')
        for i, _ in enumerate(self.js.get('dom_access') or []):
            if i not in self.dom_reads_selected:
                self.omit(f'/javascript/dom_access/{i}', 'duplicate classified read or other diagnostic DOM observation; selected source-bound reads shown')
        if self.js.get('execution_trace'):
            self.omit('/javascript/execution_trace', 'diagnostic traversal data; source-bound semantic occurrences shown')
        return self.blocks


def build_javascript_text_context(record, raw, *, native=None, audit=None, text_chars=1600, max_bytes=200_000):
    from .model_text import TextContext
    if record.get('layer') != 'l3':
        raise ValueError('javascript_context_requires_l3_record')
    if type(text_chars) is not int or text_chars < 3 or type(max_bytes) is not int or max_bytes < 1:
        raise ValueError('javascript_text_budget_invalid')
    validate_input_bundle([record], {'l3': raw})
    validate_native_input(record, raw, native)
    builder = _JS(record, raw, text_chars)
    blocks = builder.build()
    body, mapping = assemble(blocks)
    if len(body.encode('utf-8')) > max_bytes:
        raise ValueError('javascript_text_context_budget_exceeded')
    source = {
        'evidence': [{'id': s['id'], 'kind': 'javascript_record', 'facts': deepcopy(s)}
                     for s in record.get('signals', []) if s['id'] in JS_IDS],
        'javascript_raw': deepcopy(raw), 'javascript_record': deepcopy(record), 'javascript_native': deepcopy(native),
        'line_map': builder.line_map, 'model_omissions': builder.omissions, 'unreviewed_layers': ['l3_html'],
        'javascript_review_input': {'record': deepcopy(record), 'raw': deepcopy(raw), 'native': deepcopy(native),
                                    'text_chars': text_chars, 'max_bytes': max_bytes},
        'selection_contract': {
            'scope': 'javascript static observations only; HTML evidence used only for source-field binding',
            'semantic_scope': 'limited static parser; absence and empty control context do not establish runtime behavior',
            'dataflow_scope': 'producer-recorded associations, not full ECMAScript value semantics or observed transmission',
            'text_selection': 'exact source range, bounded head/tail with full source preserved',
        },
    }
    result = TextContext(body, blocks, mapping, source, VERSION)
    if audit is not None:
        audit.update(result.audit())
    return result


def validate_javascript_text_document(document):
    inputs = document.source_context.get('javascript_review_input')
    if not isinstance(inputs, dict):
        raise ValueError('javascript_text_missing_review_input')
    rebuilt = build_javascript_text_context(**inputs)
    if (document.version != VERSION or document.body != rebuilt.body or document.source_map != rebuilt.source_map
            or [asdict(b) for b in document.blocks] != [asdict(b) for b in rebuilt.blocks]):
        raise ValueError('javascript_reviewed_body_or_mapping_changed')
    if canonical(document.source_context) != canonical(rebuilt.source_context):
        raise ValueError('javascript_audit_input_or_selection_changed')
    return document
