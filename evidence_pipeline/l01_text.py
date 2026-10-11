"""Render the approved L0/L1 selection as locally understandable text blocks.

The input is the restored, already selected model context. This module does not
reanalyze URLs, query infrastructure, or select additional raw/record fields.
Evidence identities stay on TextBlock for the server's source mapping only.
"""
from copy import deepcopy

from .l0_context import KINDS as L0_KINDS, validate_l0_selection
from .l1_context import KINDS as L1_KINDS, validate_l1_selection
from .text_blocks import TextBlock, field, nested_fields
from .presentation_items import item
from .public_explanations import infrastructure, url_subject, url_observation

PUBLIC_L0_TITLES = {
    'IP_호스트': 'IP 주소를 사용하는 호스트',
    '피싱_빈발_TLD_목록_일치': '최상위 도메인과 참조 목록의 대조',
    '무료_발급_도메인': '사용자 주소 발급 도메인',
    '호스트_단어_분리': '호스트를 이루는 단어',
    'IDN_문자_변환': '국제화 도메인의 문자 표기',
    '이중_확장자': '파일 이름의 확장자 구성',
    '단축_서비스_목록_일치': '단축 서비스 참조 목록과의 일치',
    '쿼리의_외부_주소': '쿼리에 포함된 외부 주소',
    '접속_호스트_교란': 'URL의 사용자 정보와 접속 호스트',
    '서브도메인_구조_이상': '서브도메인의 접미사 형태',
}


def _public_l0(value):
    # Translate schema labels only. Supplied URL strings and values stay intact.
    labels = {'서브도메인에서_발견한_부분': '서브도메인에서 접미사 목록과 일치한 부분',
              'suffix_순번': '해당 부분의 위치 (0부터)', '일치한_suffix': '일치한 접미사',
              '부분_순번': '해당 부분의 위치 (0부터)', '분리된_단어': '구성 단어',
              '원래_부분': '원래 표기'}
    if isinstance(value, dict):
        return {labels.get(key, key): _public_l0(v) for key, v in value.items()}
    if isinstance(value, list):
        return [_public_l0(v) for v in value]
    return value


def _ids(*rows):
    return tuple(dict.fromkeys(row['id'] for row in rows))


def _items(label, values):
    return [label + ':', *nested_fields(values, indent='  ')]


def render_l0(source: dict) -> list[TextBlock]:
    rows = [row for row in source.get('evidence', []) if row.get('kind') in L0_KINDS]
    if not rows:
        return []
    validate_l0_selection(source)
    subject = next(row for row in rows if row['kind'] == 'url_subject')
    facts = subject['facts']
    url = source['requested_urls'][facts['원본 URL']['requested_url_index']]
    lines = field('원본 URL', url)
    for key in ('접속 호스트', '등록 도메인', '서브도메인'):
        if key in facts:
            lines += field(key, facts[key])
    blocks = [TextBlock('L0 URL 문자열 관찰', lines, _ids(subject),
                       [item('URL 구성', lines, basis='url_structure', evidence_ids=_ids(subject),
                             plain=url_subject(facts))])]
    for row in rows:
        if row['kind'] != 'url_observation':
            continue
        observed = row['facts']
        lines = []
        public_lines = []
        for index, occurrence in enumerate(observed['관찰'], 1):
            lines.append('관찰:' if len(observed['관찰']) == 1 else f'관찰 {index}:')
            # Only the projection's explicit common-subject wrapper is a ref.
            # Arbitrary names/values inside observed URL data stay untouched.
            if set(occurrence) == {'공통 대상'}:
                if occurrence['공통 대상'] != {'evidence_ref': subject['id']}:
                    raise ValueError('unresolved_l0_text_subject')
                target = {key: value for key, value in facts.items() if key != '원본 URL'}
                lines += nested_fields(target, indent='  ') if target else ['  위 원본 URL에 대한 관찰.']
                public_lines += nested_fields(_public_l0(target))
            else:
                lines += nested_fields(occurrence, indent='  ')
                if len(observed['관찰']) > 1:
                    public_lines.append(f'관찰 {index}:')
                public_lines += nested_fields(_public_l0(occurrence))
        public = item(observed['검사'], public_lines, basis='url_structure', evidence_ids=_ids(subject, row),
                      plain=url_observation(observed['검사'], observed['관찰']))
        public['public_title'] = PUBLIC_L0_TITLES.get(observed['검사'], observed['검사'])
        public['public_section_title'] = public['public_title']
        lines += field('판단에 쓸 점', observed['판단에 쓸 점'])
        blocks.append(TextBlock(observed['검사'], lines, _ids(subject, row), [public]))
    guide = source['reading_guide']['l0']['추가 판단 안내']
    lines = ['다음은 검토 지시이며 관측 사실이나 목록 불일치 결과가 아니다.']
    for name, text in guide.items():
        lines += field(name, text)
    blocks.append(TextBlock('L0 추가 판단 안내', lines, _ids(subject)))
    return blocks


def _limits(facts):
    lines = []
    if 'status' in facts:
        label = {'partial': '일부 정보를 확보하지 못했다.',
                 'not_observed': '조회 정보를 확보하지 못했다.'}.get(facts['status'])
        if label is None:
            raise ValueError('unsupported_l1_text_status')
        lines.append(label)
    if 'reason' in facts:
        lines += field('기록된 사유', facts['reason'])
    return lines


def _cname(facts):
    lines = []
    if 'cname_relations' in facts:
        lines.append('관측된 CNAME 이름 연결:')
        for relation in facts['cname_relations']:
            lines += field('  이름', relation['from_domain'])
            lines += field('  연결된 이름', relation['to_domain'])
    if 'cname_chain' in facts:
        lines += _items('관측된 CNAME 응답', facts['cname_chain'])
    return lines


def _networks(groups, ip_key, *, public=False):
    lines = []
    for group in groups:
        if lines:
            lines.append('')
        # The existing projection only groups complete, equal network facts.
        lines += field('IP', ', '.join(group[ip_key]))
        if group.get('ip_asn') == 'not_observed':
            if not public:
                lines.append('IP·ASN 정보를 확보하지 못했다.')
            continue
        if len(group[ip_key]) > 1:
            lines.append('위 IP들에서 공통으로 조회된 네트워크 정보:')
        for key, label in [('asn', 'ASN'), ('prefix', 'IP 대역'), ('org', '조직')]:
            if key in group:
                value = group[key]
                if key == 'org' and value == 'not_observed':
                    if not public:
                        lines.append('조직 정보는 확보하지 못했다.')
                else:
                    lines += field(label, value)
    return lines


def _response(facts):
    lines = []
    if 'response' in facts:
        lines += field('조회 응답', facts['response'])
    if 'response_codes' in facts:
        lines += _items('관측된 응답 코드', facts['response_codes'])
    return lines


def render_l1(source: dict) -> list[TextBlock]:
    rows = [row for row in source.get('evidence', []) if row.get('kind') in L1_KINDS]
    subject = (source.get('layer_subjects') or {}).get('l1')
    if subject is None and not rows:
        return []
    validate_l1_selection(source)
    subject = subject or {}
    host, domain = subject.get('lookup_host'), subject.get('registered_domain')
    lines = []
    if host and domain and host == domain:
        lines += field('조회 호스트와 등록 도메인', host)
    else:
        if host:
            lines += field('조회 호스트', host)
        if domain:
            lines += field('등록 도메인', domain)
    if not lines:
        lines = ['조회 대상이 제공된 결과에 기록되어 있지 않다.']
    blocks = [TextBlock('L1 인프라 조회', lines, _ids(*rows))]

    def target(row, registration=False):
        return row['facts'].get('query_target') or (domain if registration else host)

    # Registered NS lists are placed beside the corresponding failed DNS NS
    # observation. If more than one occurrence could match, do not conflate it.
    linked_rdap = {}
    for row in rows:
        if row['kind'] != 'dns_ns_registration':
            continue
        candidates = [other for other in rows if other['kind'] == 'rdap'
                      and other['facts'].get('nameservers') and target(row, True)
                      and target(other, True) == target(row, True)]
        peers = [other for other in rows if other['kind'] == 'dns_ns_registration'
                 and target(other, True) == target(row, True)]
        if len(candidates) == len(peers) == 1:
            linked_rdap[row['id']] = candidates[0]
    attached = {row['id'] for row in linked_rdap.values()}

    for row in rows:
        kind, facts = row['kind'], deepcopy(row['facts'])
        registration = kind in {'dns_ns_registration', 'dns_rdap_ns_comparison', 'rdap'}
        query_target = target(row, registration)
        scoped = field('대상', query_target) if query_target else []
        ids = _ids(row)
        public_lines = []
        if kind in {'dns_a_ip_asn', 'dns_a', 'ip_asn'}:
            title = {'dns_a_ip_asn': 'DNS A · IP/ASN', 'dns_a': 'DNS A', 'ip_asn': 'IP/ASN'}[kind]
            lines = field('조회 호스트', query_target) if 'query_target' in facts else []
            if 'address_selection' in facts:
                members = sum(len(group['ipv4']) for group in facts.get('networks', [])) if kind == 'dns_a_ip_asn' else len(facts.get('ipv4', []))
                if members == 2:
                    lines.append(facts['address_selection'] + '를 조회했다.')
                else:
                    lines += field('IP 조회 대상 선택 기준', facts['address_selection'])
            if 'networks' in facts:
                lines += _networks(facts['networks'], 'ipv4' if kind == 'dns_a_ip_asn' else 'ip')
            if 'ipv4' in facts:
                lines += _items('IP', facts['ipv4']) if facts['ipv4'] else ['DNS A 응답에 IPv4 주소가 없었다.']
            if facts.get('networks'):
                public_lines += _networks(facts['networks'], 'ipv4' if kind == 'dns_a_ip_asn' else 'ip', public=True)
            if facts.get('ipv4'):
                public_lines += _items('IP', facts['ipv4'])
            public_lines += _response(facts) + _cname(facts)
            lines += _response(facts) + _cname(facts) + _limits(facts)
        elif kind == 'dns_rdap_ns_comparison':
            title = 'DNS NS · RDAP NS 대조'
            lines = []
            prefix = f'등록 도메인 {query_target}의' if query_target else '조회한 등록 도메인의'
            if facts['status'] == 'matched':
                lines.append(prefix + ' DNS NS 목록과 RDAP에 등록된 NS 목록이 일치한다.')
            else:
                lines.append(prefix + ' DNS NS 목록과 RDAP에 등록된 NS 목록에 차이가 있다.')
                if facts.get('dns_only'):
                    lines += _items('DNS NS에만 있는 이름', facts['dns_only'])
                if facts.get('rdap_only'):
                    lines += _items('RDAP NS에만 있는 이름', facts['rdap_only'])
            public_lines = list(lines)
        elif kind in {'dns_ns_host', 'dns_ns_registration'}:
            title = '호스트 DNS NS' if kind == 'dns_ns_host' else 'DNS NS · RDAP NS 대조'
            lines = field('조회 호스트' if kind == 'dns_ns_host' else '등록 도메인', query_target) if query_target else []
            if 'nameservers' in facts:
                lines += _items('DNS에서 조회된 NS', facts['nameservers'])
                if facts['nameservers']:
                    public_lines += _items('DNS에서 조회된 NS', facts['nameservers'])
            public_lines += _response(facts) + _cname(facts)
            lines += _response(facts) + _cname(facts) + _limits(facts)
            if kind == 'dns_ns_registration':
                lines.append('이 DNS NS 조회에서는 NS 목록을 확보하지 못해 RDAP에 등록된 NS와 비교할 수 없다.')
                linked = linked_rdap.get(row['id'])
                if linked is not None:
                    lines += _items('RDAP에 등록된 NS', linked['facts']['nameservers'])
                    public_lines += _items('RDAP에 등록된 NS', linked['facts']['nameservers'])
                    facts['nameservers'] = linked['facts']['nameservers']
                    ids = _ids(row, linked)
        elif kind == 'rdap':
            title = '도메인 등록 정보'
            lines = list(scoped)
            for key, label in [('registration', '등록 시각'), ('expiration', '등록 만료 시각'),
                               ('last_changed', '등록정보 최종 변경 시각')]:
                if key in facts:
                    lines += field(label, facts[key])
            if 'registrar' in facts:
                registrar = facts['registrar']
                if isinstance(registrar, dict):
                    if 'name' in registrar:
                        lines += field('등록대행사', registrar['name'])
                    if 'iana_id' in registrar:
                        lines += field('등록대행사 IANA ID', registrar['iana_id'])
                else:
                    lines += field('등록대행사', registrar)
            if 'domain_status' in facts:
                lines += _items('도메인 상태', facts['domain_status'])
            if 'registered' in facts:
                lines += field('RDAP의 등록 여부 응답', '등록됨' if facts['registered'] else '등록되지 않음')
            if 'nameservers' in facts and row['id'] not in attached:
                lines += _items('RDAP에 등록된 NS', facts['nameservers'])
            public_lines = list(lines[len(scoped):]) + _response(facts)
            lines += _response(facts) + _limits(facts)
            # An NS-only RDAP row is already represented beside the DNS failure.
            if row['id'] in attached and set(facts) <= {'nameservers', 'query_target'}:
                continue
        elif kind == 'infrastructure_observation':
            title = '인프라 조회 범위'
            lines = scoped
            if 'lookup' in facts:
                lines += field('조회 항목', facts['lookup'])
            lines += _limits(facts)
        else:
            raise ValueError('unsupported_l1_text_kind')
        public = ([item(title + (f' — {query_target}' if query_target else ''),
                        scoped + public_lines, basis='observed_response', evidence_ids=ids,
                        plain=infrastructure(kind, facts, query_target))]
                  if public_lines else [])
        blocks.append(TextBlock(title, lines, ids, public))
    return blocks
