"""Plain public wording from already selected values, never from rendered prose.

These helpers describe technical facts. They do not interpret URL risk, choose
facts, look up owners, or turn static declarations into observed execution.
"""
from datetime import datetime


def plain(title, text):
    return {'title': title, 'text': text}


def url_subject(facts):
    host = facts.get('접속 호스트')
    return plain('입력 주소의 접속 대상', f'입력한 URL의 접속 대상은 {host}입니다.' if host else '분석 대상으로 입력된 URL입니다.')


def url_observation(name, occurrences):
    descriptions = {
        'IP_호스트': ('숫자로 된 접속 주소', 'URL의 접속 대상에 도메인 이름 대신 IP 주소가 쓰였습니다.'),
        '피싱_빈발_TLD_목록_일치': ('주소 끝부분과 참조 목록', '주소 끝부분이 분석에 사용한 피싱 빈발 최상위 도메인 목록의 항목과 맞습니다. 목록 일치만으로 이 URL의 악성 여부가 정해지지는 않습니다.'),
        '무료_발급_도메인': ('사용자에게 주소를 발급하는 서비스', '분석에 사용한 참조 자료에서 이 도메인은 사용자에게 하위 주소를 발급하는 서비스로 분류됩니다.'),
        '호스트_단어_분리': ('주소 이름을 이루는 단어', '주소 이름의 일부가 구분자를 기준으로 여러 단어로 나뉩니다.'),
        'IDN_문자_변환': ('주소의 문자 표기 비교', '국제화 도메인의 문자 표기와 분석용 비교 표기에 차이가 있습니다.'),
        '이중_확장자': ('파일 이름처럼 적힌 주소', 'URL에 파일 확장자가 두 번 이어진 문자열이 있습니다. 주소에 적힌 이름이며 실제 파일 내용이나 실행 결과는 아닙니다.'),
        '단축_서비스_목록_일치': ('짧은 주소 서비스와의 일치', '접속 주소가 분석에 사용한 단축 URL 서비스 참조 목록과 맞습니다.'),
        '쿼리의_외부_주소': ('URL 안에 포함된 다른 주소', 'URL의 추가 값에 다른 등록 도메인 또는 IP 주소를 대상으로 하는 주소가 포함돼 있습니다. 실제 이동을 확인한 결과는 아닙니다.'),
        '접속_호스트_교란': ('접속 주소 앞의 사용자 정보', 'URL에 사용자 정보가 들어 있습니다. 이 부분과 실제 접속 대상으로 해석되는 호스트를 구분해야 합니다.'),
        '서브도메인_구조_이상': ('주소 앞부분에 적힌 도메인 형태', '주소의 서브도메인 부분에 도메인 접미사 참조 목록과 맞는 문자열이 있습니다. URL의 등록 도메인은 별도로 구분됩니다.'),
    }
    title, text = descriptions[name]
    return plain(title, text)


def display_time(value):
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return dt.strftime('%Y년 %m월 %d일 %H:%M') + (' (UTC)' if dt.utcoffset() is not None and dt.utcoffset().total_seconds() == 0 else ' ' + dt.strftime('%z') if dt.utcoffset() is not None else '')
    except (TypeError, ValueError):
        return str(value)


def infrastructure(kind, facts, target):
    prefix = f'{target}의 ' if target else ''
    if kind == 'dns_rdap_ns_comparison':
        relation = {'matched': '맞습니다', 'different': '차이가 있습니다',
                    'mismatched': '차이가 있습니다'}.get(facts.get('status'))
        if relation:
            return plain('주소 안내 서버의 정보 비교', prefix + '주소 안내 서버 목록을 실제 조회와 등록 정보에서 비교했고, 두 목록이 ' + relation + '.')
    if kind in {'dns_a_ip_asn', 'dns_a', 'ip_asn'}:
        ips = facts.get('ipv4', [])
        if not ips:
            key = 'ipv4' if kind == 'dns_a_ip_asn' else 'ip'
            ips = [ip for group in facts.get('networks', []) for ip in group.get(key, [])]
        if ips:
            return plain('조회된 서버 주소', prefix + '조회 결과에 서버 IP 주소 ' + ', '.join(ips) + '이 기록됐습니다.')
    connections = facts.get('cname_relations', [])
    if connections:
        pairs = [f"{r['from_domain']} → {r['to_domain']}" for r in connections]
        return plain('주소 조회에서 연결된 이름', '주소 조회에 다음 이름 연결이 기록됐습니다: ' + '; '.join(pairs) + '. 웹페이지가 이 주소로 이동했다는 뜻은 아닙니다.')
    if kind in {'dns_ns_host', 'dns_ns_registration'} and facts.get('nameservers'):
        return plain('주소 안내 서버', prefix + '접속 위치를 안내하는 서버 이름으로 ' + ', '.join(facts['nameservers']) + '이 기록돼 있습니다.')
    if kind == 'rdap':
        parts = []
        if facts.get('registration'):
            parts.append('등록 시각은 ' + display_time(facts['registration']))
        if facts.get('expiration'):
            parts.append('등록 만료 시각은 ' + display_time(facts['expiration']))
        if parts:
            return plain('주소의 등록 정보', prefix + '주소 등록 정보에 ' + ', '.join(parts) + '으로 적혀 있습니다.')
        if facts.get('nameservers'):
            return plain('등록된 주소 안내 서버', prefix + '등록 정보에 주소 안내 서버 ' + ', '.join(facts['nameservers']) + '이 적혀 있습니다.')
        registrar = facts.get('registrar')
        if registrar:
            name = registrar.get('name') if isinstance(registrar, dict) else registrar
            if name:
                return plain('주소의 등록 대행사', prefix + f'주소 등록을 대행하는 곳으로 {name}이 적혀 있습니다.')
        if type(facts.get('registered')) is bool:
            return plain('주소의 등록 정보', prefix + '등록 여부 조회에 ' + ('등록됨' if facts['registered'] else '등록되지 않음') + '으로 응답했습니다.')
        if facts.get('domain_status'):
            return plain('주소의 등록 상태', prefix + '주소 등록 정보에 등록 상태가 기록돼 있습니다. 구체적인 상태 값은 기술 정보에서 확인할 수 있습니다.')
    if facts.get('response') or facts.get('response_codes'):
        return plain('주소 조회의 응답', prefix + '주소 조회에서 받은 응답이 기록돼 있습니다. 구체적인 응답 값은 기술 정보에서 확인할 수 있습니다.')
    if facts.get('cname_chain'):
        return plain('주소 조회에서 연결된 이름', '주소 조회에 여러 이름의 연결 경로가 기록돼 있습니다. 웹페이지의 실제 이동 경로를 뜻하지는 않습니다.')
    return None


def http_response(node, next_node=None, children=()):
    url = node.get('URL')
    code = node.get('HTTP 응답 코드')
    moved = node.get('다음 주소로의 이동 지시') == '관측됨'
    if moved and next_node and next_node.get('URL'):
        text = f"{url}에서 {next_node['URL']}로 이동하도록 응답했습니다."
    elif moved:
        text = f'{url}에서 다른 주소로 이동하도록 응답했습니다.'
    elif code == 200:
        text = f'{url}에서 페이지 요청에 대한 응답을 받았습니다.'
    elif code is not None:
        text = f'{url}에서 요청에 대한 응답을 받았고, 응답 코드는 {code}입니다.'
    else:
        return None
    for kind, values in children:
        extra = http_detail(kind, values)
        if extra:
            text += ' ' + extra['text']
    return plain('주소가 반환한 응답', text)


def http_detail(kind, facts):
    if kind == 'http_domain_relation':
        return http_relations(facts)
    if kind == 'http_file_type_match':
        selected = []
        if '목록에 해당한 확장자' in facts:
            selected.append('응답의 파일 이름에 적힌 확장자')
        if '실행파일 유형 목록에 해당한 본문 앞부분 추정 유형' in facts:
            selected.append('응답 본문 앞부분에서 추정한 파일 유형')
        subject = '와 '.join(selected) if selected else '응답의 파일 이름 또는 본문 앞부분 추정 유형'
        return plain('실행 관련 파일 목록과의 일치', subject + '이 분석에 사용한 실행 관련 파일 참조 목록과 맞습니다. 실제 파일 실행을 확인한 결과는 아닙니다.')
    if kind == 'http_content_type':
        relation = {'일치': '맞습니다', '불일치': '맞지 않습니다', '설정된 동등 유형으로 취급됨': '설정된 기준에서 같은 유형으로 취급됩니다'}.get(facts.get('유형 대조'))
        if relation:
            return plain('응답 내용의 종류 비교', '서버가 설명한 내용의 종류와 받은 본문 앞부분에서 추정한 종류가 ' + relation + '.')
        return plain('응답 내용의 종류', '서버가 설명한 내용 종류 또는 본문 앞부분에서 추정한 종류가 기록돼 있습니다.')
    descriptions = {
        'http_attachment': ('파일 받기 응답 설정', '서버 응답에 내용을 첨부파일로 받도록 안내하는 설정이 있습니다. 사용자가 파일을 받거나 실행한 결과는 아닙니다.'),
        'http_refresh': ('응답의 새로고침·이동 설정', '서버 응답에 새로고침 또는 주소 이동을 안내하는 설정이 있습니다. 해당 지시가 실행됐다는 뜻은 아닙니다.'),
        'http_domain_relation': ('이동 경로의 주소 비교', '응답에서 관측한 주소 이동 경로의 등록 도메인 관계가 기록돼 있습니다.'),
        'http_shortener_match': ('이동 대상과 짧은 주소 서비스', '응답에 적힌 이동 대상이 단축 URL 서비스 참조 목록과 맞습니다.'),
        'http_ip_instruction': ('숫자로 된 주소로의 이동 지시', '응답에 IP 주소를 대상으로 한 이동 지시가 있습니다. 해당 주소에 도착했음을 뜻하지는 않습니다.'),
    }
    return plain(*descriptions[kind]) if kind in descriptions else None


def http_relations(facts):
    parts = []
    if facts.get('등록 도메인 관계') == '관측된 이동 경로에서 변경 없음':
        parts.append('응답에서 관측한 주소 이동 경로의 등록 도메인은 바뀌지 않았습니다.')
    elif '등록 도메인 관계' in facts:
        parts.append('응답에서 관측한 주소 이동 경로에 등록 도메인의 변화가 기록돼 있습니다.')
    if 'HTTPS→HTTP 이동 지시' in facts:
        parts.append('암호화 연결 주소에서 암호화하지 않는 주소로 이동하라는 지시가 기록돼 있습니다.')
    return plain('이동 경로의 주소 비교', ' '.join(parts)) if parts else None


def certificate(facts, children=()):
    host = facts.get('inspected_host')
    comparison = facts.get('TLS 접속 호스트와 인증서 이름 대조')
    # C03 validates this finite selected enum before rendering. Translate exact
    # enum values; never re-parse arbitrary technical prose or compare names.
    scopes = {'SAN 기준': '인증서의 대체 이름 목록에서 주소의 종류에 맞는 이름을 대조한 결과입니다.',
              'SAN 없이 CN으로 보완 대조': '대체 이름 목록이 없어 주체의 이름으로 보완 대조한 결과입니다. 브라우저가 인증서를 받아들인다는 뜻은 아닙니다.',
              '과거 SAN 목록 기준; 이름 유형 미기록': '과거에 기록된 대체 이름 목록으로 비교한 결과입니다.',
              '대조 방식 미기록': '기록된 이름 대조 결과입니다.'}
    states = {f'{state} ({scope})': (state == '일치', note) for scope, note in scopes.items() for state in ('일치', '불일치')}
    matched = states.get(comparison)
    text = f'{host}을 대상으로 확인한 보안 인증서 정보입니다.' if host else '검사한 접속 대상의 보안 인증서 정보입니다.'
    if matched:
        text = ((f'{host}의 ' if host else '검사한 ') + '접속 주소와 인증서의 이름이 ' + ('맞습니다.' if matched[0] else '맞지 않습니다.') + ' ' + matched[1])
    for values in (facts, *(values for _, values in children)):
        extra = certificate_state(values)
        if extra:
            text += ' ' + extra
    return plain('주소와 보안 인증서', text)


def certificate_state(facts):
    from .l2_chain_context import VERIFY_LABEL, VERIFY_PASSED, VERIFY_FAILED, SCOPE_LABEL, FAILED_SCOPE
    from .l2_context import VALIDITY_LABEL, VALIDITY_TEXT
    parts = []
    verification = facts.get(VERIFY_LABEL)
    if verification == VERIFY_PASSED:
        parts.append('스캐너가 신뢰하도록 설정한 인증서를 기준으로 보안 인증서 검증을 통과했습니다.')
    elif verification == VERIFY_FAILED:
        parts.append('보안 인증서 검증에 실패했습니다.')
        if facts.get(SCOPE_LABEL) == FAILED_SCOPE:
            parts.append('검증을 켠 첫 접속에서 실패한 결과이며, 나중에 수집한 인증서와 같은 인증서라는 뜻은 아닙니다.')
    period = {VALIDITY_TEXT['valid']: '검사 당시 인증서의 유효기간 안에 있었습니다.',
              VALIDITY_TEXT['expired']: '검사 당시 인증서가 만료된 상태였습니다.',
              VALIDITY_TEXT['not_valid']: '검사 당시 인증서의 유효기간이 아직 시작되지 않았습니다.'}.get(facts.get(VALIDITY_LABEL))
    if period:
        parts.append(period)
    return ' '.join(parts)


def certificate_detail(kind, facts):
    titles = {'certificate_age': '인증서 유효기간의 시작 시점', 'certificate_validity': '인증서의 유효기간', 'certificate_ct_time': '인증서의 공개 기록 시점', 'certificate_verification': '보안 인증서 검증'}
    descriptions = {'certificate_age': '인증서의 유효기간 시작 이후 경과한 시간이 기록돼 있습니다. 사이트가 생긴 시점이나 인증서 발급 시점을 뜻하지는 않습니다.',
                    'certificate_validity': '검사 당시의 인증서 유효기간 상태가 기록돼 있습니다.',
                    'certificate_ct_time': '인증서 공개 기록에서 확인한 시각이 기록돼 있습니다. 사이트가 생긴 시점을 뜻하지는 않습니다.',
                    'certificate_verification': '스캐너가 신뢰하도록 설정한 인증서를 기준으로 한 보안 인증서 검증 결과입니다.'}
    return plain(titles[kind], certificate_state(facts) or descriptions[kind])


def declared_text(title, value):
    # Quote selected static text; never guess its purpose or translate its claim
    # into a fact about the operator. The full technical quotation stays intact.
    if not isinstance(value, str) or not value.strip():
        return None
    quote = ' '.join(value.split())
    if len(quote) > 180:
        quote = quote[:180] + '…'
    return plain(title, f'페이지에 다음 문구가 적혀 있습니다: “{quote}”')


def shared_metadata(key, value, equal_title=None):
    labels = {
        'og:title': '공유할 때의 제목',
        'og:description': '공유할 때의 소개 문구',
        'og:site_name': '공유할 때의 사이트 이름',
        'og:image:alt': '공유 이미지의 설명 문구',
        'og:image:width': '공유 이미지의 가로 크기',
        'og:image:height': '공유 이미지의 세로 크기',
        'og:image:type': '공유 이미지의 형식 설정',
        'og:video:width': '공유 영상의 가로 크기',
        'og:video:height': '공유 영상의 세로 크기',
        'og:video:type': '공유 영상의 형식 설정',
        'og:audio:type': '공유 소리 자료의 형식 설정',
        'og:type': '공유할 내용의 종류 설정',
        'og:locale': '공유할 때의 언어 설정',
    }
    title = labels.get(key, '페이지 공유용 설정')
    if equal_title:
        return plain(title, f'{title}이 앞의 {equal_title}과 같은 값으로 선언돼 있습니다.')
    if key in {'og:title', 'og:description', 'og:site_name', 'og:image:alt'}:
        return declared_text(title, value)
    text = f'{title}의 설정값은 “{value}”로 적혀 있습니다.' if key in labels else f'페이지 공유용 {key} 설정값은 “{value}”로 적혀 있습니다.'
    return plain(title, text + ' 실제 자료의 내용이나 표시 결과를 확인한 값은 아닙니다.')


def form_declaration(form, selected_inputs):
    action = form.get('action_url')
    if action is None:
        return plain('입력 폼의 설정', '페이지에 입력 폼과 그 속성이 선언돼 있습니다. 실제 입력이나 제출을 확인한 결과는 아닙니다.')
    kinds = []
    for _, field, classification in selected_inputs:
        credential = classification.get('credential_type')
        kind = {'password': '비밀번호', 'email': '이메일'}.get(credential)
        if kind is None:
            kind = {'password': '비밀번호', 'email': '이메일', 'search': '검색어'}.get(field.get('type'))
        if kind and kind not in kinds:
            kinds.append(kind)
    label = '·'.join(kinds) + ' 입력칸' if kinds else '입력 폼'
    return plain('입력 폼의 기본 전송 설정', f'{label}이 있고, 폼의 기본 제출 주소는 {action}로 설정돼 있습니다. 버튼별 대상이나 입력칸의 활성화·제출 조건은 다를 수 있습니다. 실제 입력이나 제출을 확인한 결과는 아닙니다.')


def html_field(field):
    kind = {'password': '비밀번호', 'email': '이메일', 'hidden': '숨김 값', 'search': '검색어'}.get(field.get('type'), '값')
    text = f'HTML에 {kind}을 담는 입력 요소가 선언돼 있습니다.'
    if field.get('disabled') is True:
        text += ' 비활성화 속성이 선언돼 있습니다.'
    if field.get('readonly') is True:
        text += ' 읽기 전용 속성이 선언돼 있습니다.'
    return plain('폼 밖의 입력 요소', text + ' 실제 입력이나 전송을 확인한 결과는 아닙니다.')


def html_link(link):
    text = link.get('text') or '표시 문구 없는 링크'
    target = link.get('destination_url')
    sentence = f'“{text}” 링크의 대상 주소는 {target}로 선언돼 있습니다.' if target is not None else f'“{text}” 링크에 원문 주소가 선언돼 있습니다.'
    if link.get('download') is not None:
        sentence += ' 파일 받기 속성도 선언돼 있습니다.'
    if link.get('target') == '_blank':
        sentence += ' 새 창이나 탭에서 열도록 설정돼 있습니다.'
    return plain('링크에 적힌 연결 대상', sentence + ' 실제 클릭이나 다운로드를 확인한 결과는 아닙니다.')


def html_frame(frame):
    target = frame.get('source_url')
    text = f'페이지 안에 {target}의 문서를 넣도록 선언돼 있습니다.' if target is not None else '페이지 안에 다른 문서를 넣는 요소가 선언돼 있습니다.'
    return plain('페이지 안에 넣는 문서', text + ' 실제로 로드되거나 실행됐다는 뜻은 아닙니다.')


def html_refresh(refresh):
    text = 'HTML에 새로고침·이동 설정이 선언돼 있습니다.'
    if refresh.get('valid') is True:
        if refresh.get('target_url') is not None:
            text = f"HTML에 {refresh['delay_seconds']}초 후 {refresh['target_url']}로 이동하도록 설정돼 있습니다."
        elif refresh.get('delay_seconds') is not None:
            text = f"HTML에 {refresh['delay_seconds']}초 후 새로고침하도록 설정돼 있습니다."
    return plain('페이지에 적힌 이동 설정', text + ' 실제 이동이나 대상 응답을 확인한 결과는 아닙니다.')


def html_control(button):
    text = '페이지에 ' + ('폼 제출용으로 지정된 버튼' if button.get('type') in {'submit', 'image'} else '기본 제출 기능이 없는 버튼') + '이 선언돼 있습니다.'
    if button.get('form_id') is None:
        text += ' 연결된 입력 폼은 기록되지 않았습니다.'
    if button.get('disabled') is True:
        text += ' 비활성화 속성이 있습니다.'
    return plain('페이지의 버튼 설정', text + ' 실제 클릭이나 제출을 확인한 결과는 아닙니다.')


def javascript_event(kind, event):
    target = event.get('destination_url')
    input_kind = {'username': '사용자명', 'password': '비밀번호', 'email': '이메일'}.get(event.get('credential_type'), '입력')
    choices = {
        'dynamic_execution': ('문자열로 코드를 만드는 구문', '코드에 문자열을 함수로 만들거나 코드로 처리하는 구문이 있습니다.'),
        'decode_operations': ('문자열을 변환하는 구문', '코드에 문자열의 표현을 변환하는 구문이 있습니다.'),
        'script_injection': ('추가 스크립트를 넣는 구문', '코드에 추가 스크립트 요소를 만들어 넣는 구문이 있습니다.' + (f" 기록된 소스 주소는 {event['url']}입니다." if event.get('url') else '')),
        'credential_access': ('입력값을 읽는 구문', f'코드에 {input_kind} 종류로 분류된 입력 요소의 값을 읽는 구문이 있습니다.'),
        'network_requests': ('서버에 요청하는 구문', f'코드에 {target}로 요청하는 구문이 있습니다.' if target else '코드에 서버로 요청하는 구문이 있습니다.'),
        'branches': ('조건에 따라 나뉘는 코드', '코드에 실행 환경의 조건에 따라 갈래를 나누는 구문이 있습니다.' + (f" 기록된 조건은 “{event['condition']}”입니다." if event.get('condition') else '')),
        'redirects': ('페이지를 이동시키는 구문', f'코드에 {target}로 페이지를 이동시키는 구문이 있습니다.' if target else '코드에 페이지 주소를 바꾸는 구문이 있습니다.'),
        'environment_access': ('접속 환경을 읽는 구문', '코드에 접속 환경의 속성을 읽는 구문이 있습니다.'),
    }
    title, text = choices[kind]
    # Describe only the static occurrence. This does not assert reachability,
    # function invocation, request success, data loss, or any actual execution.
    text += ' 실행 결과가 아닌 정적 코드 분석에서 확인한 내용입니다.'
    return plain(title, text)
