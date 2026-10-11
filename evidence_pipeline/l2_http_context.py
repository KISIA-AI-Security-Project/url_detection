"""Select recorded HTTP instructions, response facts and separate limitations.

No URL parsing, MIME classification, list matching or Refresh parsing is run here.
All original values, including omitted checks, remain in record and audit.
"""
from copy import deepcopy

HEADERS = {f'L2-H-{i:02}' for i in range(1, 9)}
NAMES = {'redirect_chain', 'redirect_domain_change', 'redirect_to_ip', 'url_shortener',
         'content_type_mismatch', 'dangerous_file_download', 'forced_download', 'http_refresh'}
PATH = '관측된 HTTP 경로'
DOWNGRADE = 'HTTPS→HTTP 이동 지시'
PATH_GUIDE = '다음 항목의 주소는 앞선 응답이 지시한 이동 대상이다. 목적지 응답 수신 여부는 각 항목에 표시한다.'
RESPONSE = 'HTTP 응답'
KIND_FIELDS = {
    'http_journey': {PATH, '경로 설명', '경로 추적', '등록 도메인 관계', DOWNGRADE},
    'http_domain_relation': {'등록 도메인 관계'},
    'http_shortener_match': {'단축 서비스 목록 일치', '목록 일치 위치'},
    'http_ip_instruction': {'IP 주소로의 이동 지시', '이동 대상'},
    'http_content_type': {'유형 대조', '서버 선언과 본문 앞부분 추정 유형', '서버가 선언한 콘텐츠 유형',
                          '수집한 본문 앞부분에서 추정한 유형', 'HTTP 경로 참조', '응답 위치'},
    'http_file_type_match': {'관측', '파일명', '목록에 해당한 확장자', '실행파일 유형 목록에 해당한 본문 앞부분 추정 유형',
                             'HTTP 경로 참조', '응답 위치'},
    'http_attachment': {'관측', '파일명', 'HTTP 경로 참조', '응답 위치'},
    'http_refresh': {'관측', '지연 시간(초)', '이동 대상', 'Refresh 헤더 원문', '관측 한계', 'HTTP 경로 참조', '응답 위치'},
    'http_observation_limit': {'관측 한계', '이유', '대상 URL', '원인 코드'},
}


def _owned(item):
    return item.get('layer') == 'l2' and (item.get('id') in HEADERS or item.get('name') in NAMES)


class HTTPSelection:
    def __init__(self, source):
        self.items = {}
        self.pointers = {}
        self.projected = {}
        self.planned = {}
        self.omitted_causes = set()
        self.limit_facts = {}
        self.journey_id = None
        for i, item in enumerate(source.get('observations', [])):
            if _owned(item):
                key = item['id']
                if key in self.items:
                    raise ValueError('duplicate_l2_http_observation')
                self.items[key] = item
                self.pointers[key] = f'/observations/{i}'
        self.active = bool(self.items)
        if not self.active:
            return
        layer = next((x for x in source.get('layers', []) if x.get('layer') == 'l2'), {})
        coverage = layer.get('coverage') or {}
        snapshot = coverage.get('shared_page_observation') or {}
        raw = source.get('l2_http_source') or {}
        response = raw.get('final_response') or {}
        original = raw.get('original_url') or snapshot.get('original_url') or (layer.get('target') or {}).get('original_url')
        self.received = next((x for x in (raw.get('response_received'), snapshot.get('response_received')) if type(x) is bool), None)
        status = response.get('status_code', snapshot.get('status_code', coverage.get('http_status_code')))
        if self.received is None:
            if 'status_code' in response or 'status_code' in snapshot:
                self.received = status is not None
            elif status is not None or coverage.get('http_response_received') is True:
                self.received = True
            # Legacy record coverage defaults missing HTTP raw to false. That
            # derived default is not evidence of a failed HTTP response.
        if self.received is False and status is not None:
            raise ValueError('l2_http_response_status_conflict')
        h01 = self.items.get('L2-H-01', {})
        evidence = h01.get('evidence') or {}
        hops = raw.get('redirect_chain', snapshot.get('redirect_chain'))
        if hops is None:
            hops = [{'source_url': a, 'destination_url': b} for a, b in
                    zip([original, *(evidence.get('chain') or [])], evidence.get('chain') or [])]
        if not isinstance(hops, list):
            raise ValueError('invalid_l2_http_path')
        if 'chain' in evidence and evidence['chain'] != [h.get('destination_url') for h in hops]:
            raise ValueError('l2_http_raw_record_journey_mismatch')
        if type(h01.get('detected')) is bool and h01['detected'] is not bool(hops):
            raise ValueError('l2_http_recorded_redirect_result_conflict')
        self.nodes = []
        if h01 and (hops or self.received is True or evidence.get('final_url')):
            current = original
            for hop in hops:
                if hop.get('source_url') != current or not isinstance(hop.get('destination_url'), str):
                    raise ValueError('l2_http_disconnected_path')
                node = {'URL': current, RESPONSE: '응답 수신', '다음 주소로의 이동 지시': '관측됨'}
                if hop.get('status_code') is not None:
                    node['HTTP 응답 코드'] = hop['status_code']
                self.nodes.append(node)
                current = hop['destination_url']
            if not isinstance(current, str) or not current:
                raise ValueError('l2_http_path_address_missing')
            last = {'URL': current, RESPONSE: '응답 수신' if self.received is True else
                    '응답을 받지 못함' if self.received is False else '응답 수신 여부 미기록'}
            observed_url = response.get('url') or snapshot.get('current_url') or raw.get('current_url')
            if self.received is True and observed_url and observed_url != current:
                raise ValueError('l2_http_response_target_mismatch')
            if status is not None and self.received is not False:
                last['HTTP 응답 코드'] = status
            if not hops and h01.get('detected') is False and self.received is True:
                last['다음 주소로의 이동 지시'] = '관측된 응답에서 없음'
            self.nodes.append(last)
            facts = {PATH: self.nodes}
            if hops:
                facts['경로 설명'] = PATH_GUIDE
            complete = next((x for x in (raw.get('redirect_journey_complete'), snapshot.get('redirect_journey_complete'))
                             if type(x) is bool), None)
            if complete is not None:
                facts['경로 추적'] = '완료됨' if complete else '완료되지 않음'
            self.planned['L2-H-01'] = ('http_journey', facts)
        # Relations are copied from their analyzers, not re-computed from URLs.
        h02 = self.items.get('L2-H-02', {})
        if type(h02.get('detected')) is bool:
            relation = '관측된 이동 경로에서 변경 있음' if h02['detected'] else '관측된 이동 경로에서 변경 없음'
            if self.nodes:
                self.planned['L2-H-01'][1]['등록 도메인 관계'] = relation
            elif self.received is not False:
                self.planned['L2-H-02'] = ('http_domain_relation', {'등록 도메인 관계': relation})
        h03 = self.items.get('L2-H-03', {})
        if h03.get('detected') is True:
            target = (h03.get('evidence') or {}).get('destination_url')
            found = next((n for n in self.nodes[1:] if n['URL'] == target), None)
            if found is not None:
                found['IP 주소로의 이동 지시'] = '관측됨'
            elif self.nodes or not target:
                raise ValueError('l2_http_ip_instruction_target_mismatch')
            else:
                self.planned['L2-H-03'] = ('http_ip_instruction', {'IP 주소로의 이동 지시': '관측됨', '이동 대상': target})
        h04 = self.items.get('L2-H-04', {})
        if h04.get('detected') is True:
            e = h04.get('evidence') or {}
            matches = e.get('matched_hops')
            if not matches:
                self.planned['L2-H-04'] = ('http_shortener_match',
                    {'단축 서비스 목록 일치': e.get('shortener_domain') or '일치한 도메인 미기록'})
            else:
                cursor = 0
                unlinked = []
                for match in matches:
                    found = next((i for i in range(cursor, len(self.nodes)) if self.nodes[i]['URL'] == match.get('url')), None)
                    if found is not None:
                        self.nodes[found]['단축 서비스 목록 일치'] = match['reference_domain']
                        cursor = found + 1
                    elif self.nodes:
                        raise ValueError('l2_http_shortener_path_mismatch')
                    else:
                        # The original URL can match a list even if HTTP failed.
                        unlinked.append({'URL': match['url'], '목록의 등록 도메인': match['reference_domain']})
                if unlinked:
                    self.planned['L2-H-04'] = ('http_shortener_match', {'목록 일치 위치': unlinked})
        for number in range(5, 9):
            key = f'L2-H-{number:02}'
            item = self.items.get(key)
            if not item:
                continue
            e = item.get('evidence') or {}
            if self.received is False:
                if item.get('detected') is True:
                    raise ValueError('l2_http_response_result_without_response')
                continue
            facts = None
            if number == 5:
                declared, inferred = e.get('declared_type'), e.get('detected_type')
                if declared is not None and inferred is not None:
                    if type(item.get('detected')) is not bool:
                        raise ValueError('l2_http_type_result_missing')
                    if declared == inferred:
                        if item['detected']:
                            raise ValueError('l2_http_type_result_inconsistent')
                        facts = {'유형 대조': '일치', '서버 선언과 본문 앞부분 추정 유형': declared}
                    else:
                        facts = {'유형 대조': '불일치' if item['detected'] else '설정된 동등 유형으로 취급됨',
                                 '서버가 선언한 콘텐츠 유형': declared, '수집한 본문 앞부분에서 추정한 유형': inferred}
                elif declared is not None or inferred is not None:
                    facts = {'유형 대조': '비교에 필요한 두 유형 중 하나가 기록되지 않음'}
                    facts['서버가 선언한 콘텐츠 유형' if declared is not None else '수집한 본문 앞부분에서 추정한 유형'] = declared if declared is not None else inferred
            elif number == 6 and item.get('detected') is True:
                checks = e.get('checks') or {}
                facts = {'관측': '파일명 확장자 또는 본문 앞부분 추정 유형이 설정된 실행 관련 목록에 해당함'}
                if e.get('filename'):
                    facts['파일명'] = e['filename']
                if checks.get('extension_match') is True:
                    facts['목록에 해당한 확장자'] = e['extension']
                if checks.get('mime_classification_match') is True:
                    facts['실행파일 유형 목록에 해당한 본문 앞부분 추정 유형'] = e['file_type']
                if not checks:
                    facts['관측'] += ' (일치한 개별 조건 미기록)'
            elif number == 7 and item.get('detected') is True:
                facts = {'관측': '응답 헤더가 첨부파일 다운로드를 지시함 (Content-Disposition: attachment)'}
                if e.get('filename'):
                    facts['파일명'] = e['filename']
            elif number == 8 and item.get('detected') is True:
                facts = {'관측': 'HTTP Refresh 응답 헤더 관측; 이 지시에 따른 이동은 수행하지 않음'}
                header = (response.get('headers') or {}).get('refresh')
                if e.get('target_url') is not None and e.get('delay_seconds') is not None:
                    facts.update({'지연 시간(초)': e['delay_seconds'], '이동 대상': e['target_url']})
                elif header is not None:
                    facts['Refresh 헤더 원문'] = header
                else:
                    facts['관측 한계'] = 'Refresh 헤더 원문 미기록'
                    if e.get('target_url') is not None:
                        facts['이동 대상'] = e['target_url']
                    if e.get('delay_seconds') is not None:
                        facts['지연 시간(초)'] = e['delay_seconds']
            if facts:
                self.planned[key] = ({5: 'http_content_type', 6: 'http_file_type_match', 7: 'http_attachment', 8: 'http_refresh'}[number], facts)
        for cause in source.get('causes', []):
            if cause.get('layer') != 'l2':
                continue
            detail = source.get('cause_types', {}).get(cause.get('type_id'), {})
            occurrence = cause.get('occurrence') or {}
            users = [item for item in source.get('observations', []) if cause['id'] in item.get('cause_ids', [])]
            owned = bool(users) and all(_owned(item) for item in users)
            is_http = (occurrence.get('stage') in {'http', 'http_body', 'body_type'} or
                       (occurrence.get('stage') == 'collection' and (cause.get('instance') or {}).get('url')))
            if owned and detail.get('code') == 'analysis_unresolved_reason_not_recorded':
                # These are placeholders generated for absent check results,
                # not recorded analyzer exceptions. Preserve each in audit;
                # response observations and actual failures are shown directly.
                self.omitted_causes.add(cause['id'])
            elif owned or is_http:
                facts = {'관측 한계': 'HTTP 검사 중 분석 실패' if detail.get('code') == 'analyzer_failed' else 'HTTP 수집 또는 분석에 기록된 제한'}
                reason = detail.get('error') or detail.get('message')
                if reason:
                    facts['이유'] = reason
                elif detail.get('code'):
                    facts['원인 코드'] = detail['code']
                target = (occurrence.get('observed_target') or {}).get('url') or (cause.get('instance') or {}).get('url')
                if target:
                    facts['대상 URL'] = target
                self.limit_facts[cause['id']] = facts
        self.fallback_absence = not self.nodes and not self.limit_facts

    def register(self, collection, value, pointer, document):
        if collection == 'observations' and _owned(value):
            key = value['id']
            if key in self.planned:
                kind, facts = self.planned[key]
                facts = deepcopy(facts)
                eid = document.add(kind, value, pointer)
                if document.source.get('l2_http_source'):
                    document.definitions[-1]['source_pointers'].append('/l2_http_source')
                document.lookup[('check', key)].append(document.definitions[-1])
                if kind == 'http_journey':
                    self.journey_id = eid
                    if document.h09.observed:
                        facts[DOWNGRADE] = '관측됨'
                        document.definitions[-1]['source_pointers'].append(f'/observations/{document.h09.selected[0][0]}')
                    for identifier in ('L2-H-02', 'L2-H-03', 'L2-H-04'):
                        if identifier in self.items:
                            document.definitions[-1]['source_pointers'].append(self.pointers[identifier])
                elif key in {'L2-H-05', 'L2-H-06', 'L2-H-07', 'L2-H-08'} and self.journey_id:
                    facts['HTTP 경로 참조'] = {'evidence_ref': self.journey_id}
                    facts['응답 위치'] = len(self.nodes)
                self.projected[eid] = facts
            elif key == 'L2-H-01' and self.fallback_absence:
                eid = document.add('http_observation_limit', value, pointer)
                self.projected[eid] = {'관측 한계': 'HTTP 응답을 받지 못함; 세부 원인 미기록' if self.received is False else 'HTTP 응답 수신 여부와 경로 관측 결과 미기록'}
            document.model_omissions.append({'source': pointer, 'reason': 'http_record_wrapper_retained_in_audit_selected_response_facts_only'})
            return True
        if collection == 'causes' and value.get('id') in self.omitted_causes:
            document.model_omissions.append({'source': pointer, 'reason': 'http_unresolved_placeholders_retained_in_audit_actual_observations_and_failures_selected'})
            return True
        if collection == 'causes' and value.get('id') in self.limit_facts:
            eid = document.add('http_observation_limit', value, pointer)
            document.lookup[('limitation', value['id'])].append(document.definitions[-1])
            self.projected[eid] = deepcopy(self.limit_facts[value['id']])
            return True
        return False

    def prepare_coverage(self, value):
        if not self.active or value.get('layer') != 'l2':
            return value
        # Detailed HTTP coverage is represented by path, selected facts and
        # distinct limits. Keep full coverage in the audit source bundle.
        coverage = value.get('coverage') or {}
        for key in list(coverage):
            if key.startswith('http_') or key in {'shared_page_observation', 'file_execution_observed'}:
                coverage.pop(key)
        value.pop('target', None)
        for key in ('status', 'execution', 'acquisition', 'analysis', 'provenance'):
            value.pop(key, None)
        return value

    def visible_occurrence(self, occurrence):
        if self.active and isinstance(occurrence, dict) and 'affected_signal_ids' in occurrence:
            occurrence['affected_signal_ids'] = [x for x in occurrence['affected_signal_ids'] if x not in HEADERS]
            if not occurrence['affected_signal_ids']:
                occurrence.pop('affected_signal_ids')
        return occurrence


def validate_http_selection(context):
    rows = context.get('evidence', [])
    journeys = {r['id']: r['facts'] for r in rows if r.get('kind') == 'http_journey'}
    if len(journeys) > 1:
        raise ValueError('duplicate_http_journey')
    for row in rows:
        kind, facts = row.get('kind'), row.get('facts') or {}
        if kind == 'check' and _owned(facts):
            raise ValueError('http_record_wrapper_leaked_to_model_context')
        if kind not in KIND_FIELDS:
            continue
        if not facts or set(facts) - KIND_FIELDS[kind]:
            raise ValueError('invalid_http_model_fields')
        def valid_values(value):
            if value is None or value == [] or value == {}:
                raise ValueError('empty_http_model_field')
            if isinstance(value, dict):
                for child in value.values(): valid_values(child)
            elif isinstance(value, list):
                for child in value: valid_values(child)
        valid_values(facts)
        if kind == 'http_journey':
            nodes = facts.get(PATH)
            if not isinstance(nodes, list) or not nodes:
                raise ValueError('invalid_http_journey')
            for i, node in enumerate(nodes):
                if set(node) - {'URL', RESPONSE, 'HTTP 응답 코드', '다음 주소로의 이동 지시', 'IP 주소로의 이동 지시', '단축 서비스 목록 일치'}:
                    raise ValueError('invalid_http_path_fields')
                if not isinstance(node.get('URL'), str) or node.get(RESPONSE) not in {'이동 지시가 포함된 응답 수신', '응답 수신', '응답을 받지 못함', '응답 수신 여부 미기록'}:
                    raise ValueError('invalid_http_response_observation')
                if i < len(nodes)-1 and node.get('다음 주소로의 이동 지시') != '관측됨':
                    raise ValueError('http_path_without_instruction')
                if node.get(RESPONSE) == '응답을 받지 못함' and 'HTTP 응답 코드' in node:
                    raise ValueError('http_status_without_response')
            if len(nodes)>1 and facts.get('경로 설명') != PATH_GUIDE:
                raise ValueError('http_path_scope_missing')
            if DOWNGRADE in facts and (facts[DOWNGRADE] != '관측됨' or len(nodes) < 2):
                raise ValueError('invalid_h09_instruction_in_path')
        if kind in {'http_journey','http_domain_relation'} and '등록 도메인 관계' in facts:
            if facts['등록 도메인 관계'] not in {'관측된 이동 경로에서 변경 있음','관측된 이동 경로에서 변경 없음'}:
                raise ValueError('invalid_http_domain_relation')
        if kind == 'http_content_type':
            if facts.get('유형 대조') not in {'일치','불일치','설정된 동등 유형으로 취급됨','비교에 필요한 두 유형 중 하나가 기록되지 않음'}:
                raise ValueError('invalid_http_type_relation')
            equal = '서버 선언과 본문 앞부분 추정 유형' in facts
            if equal != (facts['유형 대조']=='일치') or (equal and set(facts)&{'서버가 선언한 콘텐츠 유형','수집한 본문 앞부분에서 추정한 유형'}):
                raise ValueError('duplicate_or_missing_http_type_values')
        if kind == 'http_file_type_match':
            base = '파일명 확장자 또는 본문 앞부분 추정 유형이 설정된 실행 관련 목록에 해당함'
            if facts.get('관측') not in {base,base+' (일치한 개별 조건 미기록)'}:
                raise ValueError('invalid_http_file_type_scope')
            if facts['관측']==base and not set(facts)&{'목록에 해당한 확장자','실행파일 유형 목록에 해당한 본문 앞부분 추정 유형'}:
                raise ValueError('http_file_type_matched_condition_missing')
        if 'HTTP 경로 참조' in facts:
            ref = facts['HTTP 경로 참조']
            target = journeys.get(ref.get('evidence_ref')) if isinstance(ref, dict) else None
            if not target or set(ref) != {'evidence_ref'} or facts.get('응답 위치') != len(target[PATH]):
                raise ValueError('invalid_http_response_reference')
            if target[PATH][-1][RESPONSE] == '응답을 받지 못함':
                raise ValueError('http_fact_without_response')
        if kind == 'http_refresh' and facts.get('관측') != 'HTTP Refresh 응답 헤더 관측; 이 지시에 따른 이동은 수행하지 않음':
            raise ValueError('invalid_http_refresh_scope')
        if kind == 'http_attachment' and facts.get('관측') != '응답 헤더가 첨부파일 다운로드를 지시함 (Content-Disposition: attachment)':
            raise ValueError('invalid_http_attachment_scope')
