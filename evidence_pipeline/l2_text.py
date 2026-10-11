"""Render approved L2 selections beside the response or TLS observation they describe."""
from .text_blocks import TextBlock, field, nested_fields
from .presentation_items import item
from .public_explanations import certificate, certificate_detail, http_response, http_detail, http_relations


HTTP_KINDS = {
    'http_content_type': '콘텐츠 유형 대조',
    'http_file_type_match': '실행 관련 파일 목록 일치',
    'http_attachment': '첨부파일 다운로드 지시',
    'http_refresh': 'Refresh 응답 헤더',
}
CERT_KINDS = {
    'certificate_age': '유효기간 시작 후 경과',
    'certificate_validity': '유효기간 상태',
    'certificate_ct_time': 'CT 기록 시각',
    'certificate_verification': '서버 인증서 검증',
    'certificate_age_limit': '유효기간 시작 시각 관측 한계',
    'certificate_validity_limit': '유효기간 상태 관측 한계',
    'certificate_name_limit': '인증서 이름 대조 관측 한계',
    'certificate_signature_limit': '자체 서명 관측 한계',
    'certificate_verification_limit': '서버 인증서 검증 관측 한계',
    'certificate_ct_limit': 'CT 관측 한계',
    'tls_observation_limit': 'TLS 관측 한계',
}
OTHER_HTTP = {'http_domain_relation', 'http_shortener_match', 'http_ip_instruction',
              'http_observation_limit'}
TITLES = {'http_domain_relation': '등록 도메인 관계',
          'http_shortener_match': '단축 서비스 목록 일치',
          'http_ip_instruction': 'IP 주소로의 이동 지시',
          'http_observation_limit': 'HTTP 관측 한계'}
PHASE = {'tls': 'TLS 접속·인증서 수집', 'ct': 'CT 조회', 'analysis': '분석',
         'http': 'HTTP 수집', 'http_body': 'HTTP 본문 수집', 'body_type': '본문 유형 분석',
         'collection': '수집'}
KNOWN = {'coverage', 'technical', 'http_journey', 'limitation', *HTTP_KINDS, *CERT_KINDS, *OTHER_HTTP}


def _ref(facts, key):
    value = facts.get(key)
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {'evidence_ref'}:
        raise ValueError('text_unresolved_l2_relationship:' + key)
    return value['evidence_ref']


def _facts(facts, excluded=()):
    selected = {key: value for key, value in facts.items() if key not in excluded}
    if any(key in selected for key in ('evidence_ref', 'certificate_ref', 'HTTP 경로 참조')):
        raise ValueError('text_unresolved_l2_relationship')
    return nested_fields(selected)


def _public_http(kind, facts):
    excluded = {'HTTP 경로 참조', '응답 위치', '관측 한계'}
    if kind == 'http_content_type' and facts.get('유형 대조') not in {'일치', '불일치', '설정된 동등 유형으로 취급됨'}:
        excluded.add('유형 대조')
    return _facts(facts, excluded)


def _body(coverage):
    complete, truncated = coverage.get('body_complete'), coverage.get('body_truncated')
    if complete is True and truncated is True:
        raise ValueError('text_conflicting_body_completeness')
    if complete is True:
        return ['응답 본문 수집: 끝까지 수집함.']
    if truncated is True:
        return ['응답 본문 수집: 일부만 수집됐으며 잘림이 기록됨.']
    if complete is False:
        return ['응답 본문 수집: 끝까지 수집되지 않음.']
    if truncated is False:
        return ['응답 본문 수집: 잘림은 없다고 기록됐으나 전체 수집 여부는 미기록.']
    return []


def _limit(facts, known_ids):
    occurrence = facts.get('occurrence') or {}
    description = facts.get('description') or {}
    detail = facts.get('observed_detail') or {}
    stage = occurrence.get('stage') or description.get('stage')
    lines = field('발생 단계', PHASE.get(stage, stage)) if stage else []
    target = occurrence.get('observed_target') or {}
    if isinstance(target, dict):
        for key, label in [('url', '대상 URL'), ('hostname', '대상 호스트'), ('host', '대상 호스트')]:
            if target.get(key) is not None:
                lines.extend(field(label, target[key]))
    for key, label in [('error', '기록된 이유'), ('message', '기록된 설명'), ('code', '원인 코드')]:
        if description.get(key) is not None:
            lines.extend(field(label, description[key]))
    # Keep observed detail values; storage identity, grouping and missing-value
    # wrappers do not enter the body. These remain in the unchanged source audit.
    labels = {'host': '접속 대상', 'hostname': '검사 호스트', 'url': '대상 URL',
              'error_type': '오류 유형', 'error': '오류 내용', 'reason': '기록된 이유',
              'operation': '수행 항목', 'status_code': 'HTTP 응답 코드',
              'message': '기록된 설명', 'code': '원인 코드', 'analyzer': '검사 항목'}
    internal = {'impact_scope', 'not_recorded', 'no_entries_recorded', 'occurrence_id',
                'response_observation', 'source_hint', 'source_hints', 'reported_in'}
    for key, value in detail.items():
        if key in internal or value is None or value == [] or value == {}:
            continue
        if (key in target and target[key] == value or
                key in {'host', 'hostname', 'url'} and value in target.values()):
            continue
        lines.extend(nested_fields({labels.get(key, key): value}))
    refs = []
    for ref in facts.get('affected_checks', []):
        eid = _ref({'link': ref}, 'link')
        if eid not in known_ids:
            raise ValueError('text_missing_l2_limit_relationship')
        refs.append(eid)
    return lines or ['수집 또는 분석의 제한이 기록됨. 세부 이유는 기록되지 않음.'], refs


def render_l2(source):
    rows = source.get('evidence', [])
    selected = [r for r in rows if r['kind'] in KNOWN and (
        r['kind'] not in {'coverage', 'limitation'} or
        r['facts'].get('layer', (r['facts'].get('occurrence') or {}).get('layer')) == 'l2')]
    if not selected:
        return []
    coverage_rows = [r for r in selected if r['kind'] == 'coverage']
    if len(coverage_rows) > 1:
        raise ValueError('text_multiple_l2_collection_observations_require_separate_sections')
    coverage_row = coverage_rows[0] if coverage_rows else None
    coverage = coverage_row['facts'].get('coverage', {}) if coverage_row else {}
    blocks, consumed = [], set()
    by_id = {r['id']: r for r in selected}

    def add(title, lines, ids, public_items=()):
        unique = tuple(dict.fromkeys(ids))
        if lines:
            blocks.append(TextBlock(title, lines, unique, list(public_items)))
        consumed.update(unique)

    journeys = [r for r in selected if r['kind'] == 'http_journey']
    for journey in journeys:
        facts = journey['facts']
        nodes = facts['관측된 HTTP 경로']
        lines, ids, public_items = [], [journey['id']], []
        if facts.get('경로 설명'):
            lines.append(facts['경로 설명'])
        for index, node in enumerate(nodes, 1):
            if lines:
                lines.append('')
            lines.append(f'경로의 {index}번째 주소')
            lines.extend(_facts(node))
            public_lines = _facts(node, {'HTTP 응답'}) if node.get('HTTP 응답') == '응답 수신' else []
            if index > 1 and nodes[index - 2].get('다음 주소로의 이동 지시') == '관측됨':
                # A Location target remains observed even when its connection fails.
                # State it beside the originating response, not as a received page.
                if public_items:
                    public_items[-1]['lines'] += field('이 응답이 지시한 다음 주소', node['URL'])
                    for key in ('IP 주소로의 이동 지시', '단축 서비스 목록 일치'):
                        if key in node and not public_lines:
                            public_items[-1]['lines'] += field('이동 대상의 ' + key, node[key])
            public_ids = [journey['id']]
            public_children = []
            if len(journeys) == 1 and index == len(nodes) and node.get('HTTP 응답') == '응답 수신':
                body = _body(coverage)
                lines.extend(body)
                if coverage_row and body:
                    ids.append(coverage_row['id'])
            for child in selected:
                if child['kind'] not in HTTP_KINDS:
                    continue
                cf = child['facts']
                if _ref(cf, 'HTTP 경로 참조') == journey['id'] and cf.get('응답 위치') == index:
                    lines.append(HTTP_KINDS[child['kind']] + ':')
                    lines.extend('  ' + line for line in _facts(cf, {'HTTP 경로 참조', '응답 위치'}))
                    ids.append(child['id'])
                    if public_lines:
                        public_lines += [HTTP_KINDS[child['kind']] + ':', *_public_http(child['kind'], cf)]
                        public_ids.append(child['id'])
                        public_children.append((child['kind'], cf))
            if public_lines:
                public_items.append(item(f'경로의 {index}번째 주소', public_lines,
                                         basis='observed_response', evidence_ids=public_ids,
                                         plain=http_response(node, nodes[index] if index < len(nodes) else None, public_children)))
        lines.extend(_facts(facts, {'관측된 HTTP 경로', '경로 설명'}))
        relation_lines = _facts({k: facts[k] for k in ('등록 도메인 관계', 'HTTPS→HTTP 이동 지시') if k in facts})
        if relation_lines:
            public_items.append(item('이동 경로의 주소 관계', relation_lines,
                                     basis='observed_response', evidence_ids=[journey['id']], plain=http_relations(facts)))
        add('L2 HTTP 관측', lines, ids, public_items)
    if not journeys:
        body = _body(coverage)
        if body:
            target = (coverage_row['facts'].get('target') or {}).get('final_url') if coverage_row else None
            body = ([*field('응답 URL', target)] if target else
                    ['본문 수집 범위에 해당하는 응답 URL은 제공된 결과에 기록되지 않음.']) + body
            add('L2 HTTP 본문 수집 범위', body, [coverage_row['id']] if coverage_row else [])
    for row in selected:
        if row['id'] in consumed:
            continue
        kind, facts = row['kind'], row['facts']
        if kind in HTTP_KINDS:
            if 'HTTP 경로 참조' in facts:
                raise ValueError('text_http_response_relationship_not_rendered')
            add('L2 ' + HTTP_KINDS[kind], _facts(facts), [row['id']],
                [item(HTTP_KINDS[kind], _public_http(kind, facts), basis='observed_response', evidence_ids=[row['id']], plain=http_detail(kind, facts))])
        elif kind in OTHER_HTTP:
            add('L2 ' + TITLES[kind], _facts(facts), [row['id']],
                [item(TITLES[kind], _facts(facts), basis='observed_response', evidence_ids=[row['id']], plain=http_detail(kind, facts))] if kind != 'http_observation_limit' else [])

    identities = [r for r in selected if r['kind'] == 'technical']
    for identity in identities:
        facts = identity['facts']
        if facts.get('kind') != 'certificate_identity_comparison':
            raise ValueError('text_unknown_l2_technical_fact')
        lines, ids = [], [identity['id']]
        if facts.get('inspected_host') is not None:
            lines.extend(field('TLS 접속 호스트', facts['inspected_host']))
        if facts.get('scope'):
            lines.append(facts['scope'])
        if facts.get('subject_distinguished_name') is not None:
            lines.extend(field('인증서 주체 이름(DN)', facts['subject_distinguished_name']))
        lines.extend(_facts(facts, {'inspected_host', 'kind', 'scope', 'subject_distinguished_name',
                                    'not_recorded', 'no_entries_recorded'}))
        public_lines, public_ids = list(lines), list(ids)
        public_children = []
        for child in selected:
            if child['kind'] not in CERT_KINDS or _ref(child['facts'], 'certificate_ref') != identity['id']:
                continue
            lines.append('')
            lines.append(CERT_KINDS[child['kind']] + ':')
            lines.extend('  ' + line for line in _facts(child['facts'], {'certificate_ref'}))
            ids.append(child['id'])
            if not child['kind'].endswith('_limit'):
                public_lines += [CERT_KINDS[child['kind']] + ':', *_facts(child['facts'], {'certificate_ref', 'not_recorded', 'no_entries_recorded'})]
                public_ids.append(child['id'])
                public_children.append((child['kind'], child['facts']))
        add('L2 TLS 접속과 인증서', lines, ids,
            [item('인증서 — ' + str(facts.get('inspected_host') or '접속 대상'), public_lines,
                  basis='observed_response', evidence_ids=public_ids, plain=certificate(facts, public_children))])
    for row in selected:
        if row['id'] in consumed or row['kind'] not in CERT_KINDS:
            continue
        if 'certificate_ref' in row['facts']:
            raise ValueError('text_certificate_relationship_not_rendered')
        add('L2 ' + CERT_KINDS[row['kind']], _facts(row['facts']), [row['id']],
            [item(CERT_KINDS[row['kind']], _facts(row['facts'], {'not_recorded', 'no_entries_recorded'}),
                  basis='observed_response', evidence_ids=[row['id']], plain=certificate_detail(row['kind'], row['facts']))] if not row['kind'].endswith('_limit') else [])
    for row in selected:
        if row['kind'] != 'limitation':
            continue
        lines, refs = _limit(row['facts'], by_id)
        linked = next((b for b in blocks if refs and set(refs) <= set(b.evidence_ids)), None)
        if linked:
            linked.lines.extend(['', '이 관측에 기록된 제한:', *('  ' + line for line in lines)])
            linked.evidence_ids += (row['id'],)
            consumed.add(row['id'])
        else:
            # Every occurrence remains a separate block, even with equal messages.
            add('L2 수집·분석 한계', lines, [row['id']])
    if coverage_row:
        # Coverage storage IDs/lifecycle/counts are audit-only. Where a TLS target
        # has no identity row, preserve its factual target/scope here once.
        if not identities and coverage.get('tls_target'):
            add('L2 TLS 접속 대상', [*field('TLS 접속 호스트', coverage['tls_target']),
                'TLS 관측은 HTTP 응답 수집과 별도 접속에서 수행됨.'], [coverage_row['id']])
        consumed.add(coverage_row['id'])
    if set(by_id) - consumed:
        raise ValueError('text_unhandled_l2_evidence')
    guide = source.get('reading_guide') or {}
    http_block = next((b for b in blocks if b.title.startswith('L2 HTTP')), None)
    if http_block and guide.get('HTTP 관측'):
        http_block.lines.extend(['', guide['HTTP 관측']])
    tls_block = next((b for b in blocks if b.title == 'L2 TLS 접속과 인증서'), None)
    if tls_block and guide.get('인증서 시간'):
        tls_block.lines.extend(['', guide['인증서 시간']])
    return blocks
