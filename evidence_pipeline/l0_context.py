"""Project compact L0 records into model facts without re-running URL analysis.

The source bundle keeps the complete stored raw/record for audit. Only the
selected facts below enter the model document; instructions are not evidence.
"""
from copy import deepcopy


SOURCE_KEY = 'l0_url_observations'
KINDS = {'url_subject', 'url_observation'}
ALWAYS_GUIDANCE = {
    'DGA_패턴': '도메인 문자열이 DGA 패턴에 해당하는지 다른 관찰과 함께 판단한다.',
    '타이포스쿼팅': '도메인 문자열이 브랜드·서비스 이름의 오타나 유사 표기를 이용한 타이포스쿼팅인지 판단한다.',
}
CONDITIONAL_GUIDANCE = {
    '단축_서비스_목록_일치': '호스트가 단축 URL 서비스 주소일 가능성을 검토한다.',
    '무료_발급_도메인': '호스트가 서비스 이용자에게 하위 주소를 발급하는 플랫폼의 주소인지 검토한다.',
    '이중_확장자': '경로와 쿼리 값에 파일 종류를 오인시킬 수 있는 확장자 조합이 있는지 검토한다.',
}
SUBJECT_ALIASES = {
    '호스트': '접속 호스트', 'URL_호스트': '접속 호스트',
    '실제_접속_호스트': '접속 호스트',
    '등록_도메인': '등록 도메인', '실제_등록_도메인': '등록 도메인',
    'URL의_등록_도메인': '등록 도메인',
}
MODEL_METADATA_KEYS = {
    'analysis_status', 'analysis', 'execution', 'acquisition', 'errors', 'coverage',
    'provenance', 'raw_ref', 'reference_versions', 'schema_version',
    'record_contract_version', 'producer_contract', 'request_id', 'attempt',
    'sha256', 'parse_status', 'query_status', 'query_errors', 'url_standard', '목록_버전',
}
REFERENCE_HELP = (
    '원본 URL의 requested_url_index는 requested_urls의 0부터 시작하는 위치다. '
    '관찰에서 반복을 생략한 접속 호스트·등록 도메인은 공통 대상의 값이다. '
    '추가 판단 안내는 검토 지시이며 관측 사실이나 목록 불일치 결과가 아니다.'
)


def guidance_for(names):
    return {**ALWAYS_GUIDANCE,
            **{name: text for name, text in CONDITIONAL_GUIDANCE.items() if name not in names}}


class L0Projection:
    def __init__(self, bundle):
        self.bundle = bundle
        self.raw = bundle['raw']
        self.record = bundle['record']
        self.url = self.raw['raw_url']
        self.subject = {'원본 URL': {'requested_url_index': 0}}
        parsed = self.raw.get('parsed') or {}
        extracted = self.raw.get('extracted') or {}
        for name, value in (
            ('접속 호스트', parsed.get('hostname')),
            ('등록 도메인', extracted.get('registered_domain')),
            ('서브도메인', extracted.get('subdomain')),
        ):
            if value:
                self.subject[name] = deepcopy(value)
        self.projected = {}
        self.subject_id = None

    def register(self, document):
        base = '/' + SOURCE_KEY
        self.subject_id = document.add('url_subject', self.raw, base + '/raw')
        self.projected[self.subject_id] = self.subject
        groups = {}
        for index, signal in enumerate(self.record['signals']):
            pointer = f'{base}/record/signals/{index}'
            key = (signal['검사'], signal['판단에 쓸 점'])
            if key not in groups:
                eid = document.add('url_observation', signal, pointer)
                groups[key] = (eid, document.definitions[-1])
                self.projected[eid] = {
                    '검사': signal['검사'], '관찰': [], '판단에 쓸 점': signal['판단에 쓸 점'],
                }
            else:
                eid, definition = groups[key]
                definition['source_pointers'].append(pointer)
            facts = deepcopy(signal['관찰'])
            # Only these schema fields are metadata/shared subject values.
            # Query values and nested user data never pass through generic clean().
            if '목록_버전' in facts:
                facts.pop('목록_버전')
                document.model_omissions.append({
                    'source': pointer + '/관찰/목록_버전', 'reason': 'l0_reference_version_is_audit_only'})
            for field, subject_field in SUBJECT_ALIASES.items():
                if field in facts and subject_field in self.subject and facts[field] == self.subject[subject_field]:
                    facts.pop(field)
                    document.removed.append({'source': pointer + '/관찰/' + field,
                                             'represented_by': self.subject_id, 'field': subject_field})
            # Keep every occurrence, including equal observations at equal positions.
            # A source containing only a shared subject still needs its occurrence.
            if not facts:
                facts = {'공통 대상': {'evidence_ref': self.subject_id}}
            self.projected[eid]['관찰'].append(facts)
        document.model_omissions.append({
            'source': base + '/record',
            'fields': [key for key in self.record if key != 'signals'],
            'reason': 'l0_execution_errors_and_storage_metadata_are_audit_only',
        })

    def guide(self):
        return {
            '원본 URL 참조': REFERENCE_HELP,
            '공통 대상': {'evidence_ref': self.subject_id},
            '추가 판단 안내': guidance_for({signal['검사'] for signal in self.record['signals']}),
        }


def validate_l0_selection(context):
    """Reject reintroduced metadata, duplicated subject facts and wrong guidance."""
    rows = context['evidence']
    selected = [row for row in rows if row.get('kind') in KINDS]
    guide = context.get('reading_guide', {}).get('l0')
    if not selected and guide is None:
        return
    subjects = [row for row in selected if row['kind'] == 'url_subject']
    if len(subjects) != 1 or not isinstance(guide, dict):
        raise ValueError('invalid_l0_model_subject')
    subject = subjects[0]['facts']
    if not set(subject) <= {'원본 URL', '접속 호스트', '등록 도메인', '서브도메인'}:
        raise ValueError('l0_subject_metadata_leaked')
    reference = subject.get('원본 URL')
    urls = context.get('requested_urls')
    index = reference.get('requested_url_index') if isinstance(reference, dict) else None
    if (not isinstance(reference, dict) or set(reference) != {'requested_url_index'}
            or type(index) is not int or not isinstance(urls, list)
            or not 0 <= index < len(urls) or not isinstance(urls[index], str)):
        raise ValueError('invalid_l0_requested_url_reference')
    if any(not isinstance(value, str) or not value for key, value in subject.items() if key != '원본 URL'):
        raise ValueError('empty_l0_subject_field')
    names = set()
    groups = set()
    for row in rows:
        if row.get('kind') not in KINDS and row.get('facts', {}).get('layer') == 'l0':
            raise ValueError('l0_record_metadata_leaked_to_model_context')
    for row in selected:
        if row['kind'] != 'url_observation':
            continue
        facts = row['facts']
        if set(facts) != {'검사', '관찰', '판단에 쓸 점'}:
            raise ValueError('invalid_l0_model_observation')
        if any(not isinstance(facts[key], str) or not facts[key] for key in ('검사', '판단에 쓸 점')):
            raise ValueError('invalid_l0_model_observation_text')
        key = (facts['검사'], facts['판단에 쓸 점'])
        if key in groups:
            raise ValueError('repeated_l0_model_guidance')
        groups.add(key)
        names.add(facts['검사'])
        observations = facts['관찰']
        if not isinstance(observations, list) or not observations:
            raise ValueError('empty_l0_model_observation')
        for observed in observations:
            if not isinstance(observed, dict) or not observed or MODEL_METADATA_KEYS.intersection(observed):
                raise ValueError('l0_observation_metadata_leaked')
            for field, subject_field in SUBJECT_ALIASES.items():
                if field in observed and subject_field in subject and observed[field] == subject[subject_field]:
                    raise ValueError('duplicated_l0_subject_fact')
    if (set(guide) != {'원본 URL 참조', '공통 대상', '추가 판단 안내'}
            or guide['공통 대상'] != {'evidence_ref': subjects[0]['id']}
            or guide['원본 URL 참조'] != REFERENCE_HELP
            or guide['추가 판단 안내'] != guidance_for(names)):
        raise ValueError('invalid_l0_conditional_guidance')
