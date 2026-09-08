# L3 탐지 항목 설명 및 판정 기준

이 문서는 L3의 17개 Signal을 운영 화면, 보고서, Rule/LLM 입력에서 일관되게
해석하기 위한 빠른 참조다. 상세 Evidence 계약과 예외 처리는 `L3_SPEC.md`를 따른다.

## 공통 판정 원칙

- `detected=true`: 정의된 구조 또는 데이터 흐름을 Evidence로 확인했다.
- `detected=false`: 필수 입력·정책·Parser가 완전한 평가 범위에서 조건이 없었다.
- `detected=null`: 정책 부재, 입력 부족, URL 해석 실패, 관계 미확정 등으로 결론을
  낼 수 없다. 정상 또는 미탐지로 간주하지 않는다.
- `status=not_applicable`: 평가 대상 자체가 없다. 예: Form 또는 JavaScript가 없음.
- `status=error`: 파싱 실패, 잘린 Source, 정책 실행 오류 등으로 평가하지 못했다.

`detected=true`는 악성 확정이 아니다. 정상 로그인 페이지도 Credential Form,
Network Destination, Redirect Signal을 만들 수 있다. 최종 악성/정상 판정은 L3
밖의 Rule/LLM이 여러 Signal과 운영 문맥을 결합해 수행한다.

도메인 동일성은 hostname 문자열이 아니라 Public Suffix List 기반 eTLD+1으로
비교한다. 예를 들어 `login.example.com`과 `api.example.com`은 same-site다.
HTTP(S)가 아니거나 eTLD+1을 계산할 수 없는 URL은 같은 사이트 또는 외부 사이트로
추정하지 않는다.

## HTML 탐지 항목

### L3-H-01 — Credential Form

- 설명: Credential Field가 실제로 연결된 `<form>`을 식별한다. Form 밖의 독립
  입력은 세지 않는다.
- 양성: Credential Field가 하나 이상 연결된 Form ID가 1개 이상이다.
- 음성/미확정: 완전한 분류 정책에서 해당 Form이 없으면 `false`; 분류 정책이
  없거나 실패하면 `null` 또는 `error`다.
- Evidence: `form_count`, `form_ids`.

### L3-H-02 — Credential Field

- 설명: Input의 `type`, `autocomplete`, `id`, `name`, `placeholder`를 정책과
  비교해 password, email, username 필드를 식별한다. 입력값은 읽거나 저장하지 않는다.
- 양성: 정책으로 분류된 Credential Field가 1개 이상이다.
- 음성/미확정: 완전한 정책에서 일치 필드가 없으면 `false`; 정책 부재/실패는
  `null` 또는 `error`다.
- Evidence: `field_count`, `field_types`, `fields`.

### L3-H-03 — Form Action Domain

- 설명: 모든 Form의 해석된 Action eTLD+1과 현재 문서 eTLD+1 관계를 기록하는
  관측 항목이다.
- 판정: 현재 버전은 Signal 양성/음성 매핑이 미확정이므로 `detected`는 항상 `null`이다.
  대신 비교 가능하면 Form별 `domain_match=true/false`, 불가능하면 `null`을 기록한다.
- 적용 불가: Form이 없으면 `status=not_applicable`이다.
- Evidence: `forms[].action_url`, `action_etld1`, `current_etld1`, `domain_match`,
  `action_resolution`.

### L3-H-04 — External POST

- 설명: POST Form이 현재 사이트와 다른 등록 도메인으로 제출되도록 구성됐는지
  확인한다. Credential Form 여부는 보조 정보다.
- 양성: POST Form 중 하나라도 `destination_etld1 != current_etld1`이다.
- 음성/미확정: POST Form이 없으면 `not_applicable`; 모든 목적지가 same-site면
  `false`; 외부 POST는 없지만 목적지를 해석할 수 없는 Form이 있으면 `null`이다.
- Evidence: `posts[]`, `destination_url`, `destination_etld1`, `external`,
  `credential_form`.

### L3-H-05 — Brand-Domain Mismatch

- 설명: 페이지 대표 브랜드를 정책으로 하나만 식별한 뒤 현재 eTLD+1을 공식/기대
  도메인 집합과 비교한다.
- 양성: 브랜드가 유일하게 식별되고 현재 eTLD+1이 `expected_domains`에 없다.
- 음성/미확정: 공식 도메인에 포함되면 `false`; 브랜드 미식별·복수 식별·미등록,
  정책 부재, 도메인 해석 불가는 `null`이다.
- Evidence: `detected_brand`, `brand_identification_sources`,
  `brand_identification_confidence`, `current_domain`, `expected_domains`.

### L3-H-06 — Brand Resource Mismatch

- 설명: 이미지, favicon, URL형 Open Graph 리소스가 현재/공식/허용 Resource
  Domain 집합 밖에서 제공되는지 확인한다.
- 양성: 브랜드가 식별되고 완전한 Resource Policy가 있으며 하나 이상의 Resource
  Domain이 허용 집합 밖에 있다.
- 음성/미확정: 모든 해석 가능 리소스가 허용 집합 안이면 `false`; 브랜드/정책
  부재 또는 외부 리소스의 소유 관계가 미확정이면 `null`이다.
- Evidence: `resources[].resource_type`, `resource_url`, `resource_domain`,
  `detected_brand`, `current_domain`.

### L3-H-07 — HTML Redirect

- 설명: 유효한 `<meta http-equiv="refresh">`를 찾아 지연시간과 목적지를 기록한다.
  HTTP Header Refresh와 JavaScript 이동은 포함하지 않는다.
- 양성: 유효한 Meta Refresh가 존재한다.
- 음성/미확정: 없거나 형식이 유효하지 않으면 `false`; HTML 파싱 실패는 `error`다.
- Evidence: `target_url`, `delay_seconds`, `raw_content`.

### L3-H-08 — Base URL Change

- 설명: `<base href>`가 상대 링크·Form·Resource의 기준 주소를 외부 사이트로
  변경하는지 확인한다.
- 양성: 유효한 Base URL의 eTLD+1이 현재 문서 eTLD+1과 다르다.
- 음성/미확정: Base가 없거나 same-site면 `false`; URL/도메인 해석 불가는 `null`이다.
- Evidence: `base_url`, `base_etld1`, `external`.

## JavaScript 탐지 항목

현재 구현은 JavaScript를 실행하지 않고 ESTree AST로 정적 분석한다. 아래의 “호출
관측”은 API 이름이 문자열로 존재한다는 뜻이 아니라 실제 호출, 생성, 대입 또는
추적 가능한 데이터 관계가 AST에 있다는 뜻이다. 실제 실행 경로 재현은 L4 범위다.

### L3-J-01 — Dynamic Code Execution

- 설명: 문자열 또는 동적 값을 코드로 실행하는 정책 API 호출을 찾는다.
- 양성: `eval(...)`, `Function(...)`, `new Function(...)`에 해당하는 실제
  Call/New AST가 1개 이상이다.
- 음성/미확정: 완전한 정책·Source에서 호출이 없으면 `false`; 정책/Source/Parser가
  불완전하면 `null` 또는 `error`다.
- Evidence: `apis`, `execution_count`, `origins`.

### L3-J-02 — Obfuscation / Decode Chain

- 설명: Decode 결과가 변수나 인자를 통해 동적 실행 API로 전달되는 동일 데이터
  계보를 찾는다.
- 양성: 정책 Decode 호출의 결과가 J-01 실행 호출 입력으로 연결된다.
- 음성/미확정: Decode만 있거나 서로 무관한 Decode/실행은 `false`; 계보 또는 필수
  정책/Source가 불완전하면 `null` 또는 `error`다.
- Evidence: `methods`, `chain`, `execution_connected`.

### L3-J-03 — Dynamic Script Injection

- 설명: `document.createElement('script')`로 만든 요소가 `appendChild`, `append`,
  `prepend`, `insertBefore`로 DOM에 삽입되는 구조를 찾는다. 외부 도메인은 필수 조건이
  아니다.
- 양성: 추적 가능한 Script 요소 삽입 AST가 1개 이상이다.
- 음성/미확정: 완전한 Source에서 삽입 구조가 없으면 `false`; 분석이 불완전하면
  `error`다.
- Evidence: `script_count`, `urls`, `domains`.

### L3-J-04 — Network Destination

- 설명: 정책 Network API 호출에서 정적으로 해석 가능한 HTTP(S) 목적지를 추출하며
  실제 요청은 보내지 않는다.
- 양성: 목적지를 해석할 수 있는 정책 Network API 호출이 1개 이상이다. 외부
  Domain일 필요는 없다.
- 음성/미확정: 완전한 Source에서 호출이 없으면 `false`; 호출은 있으나 목적지가
  동적이라 해석 불가하면 `null`; 정책/분석 불완전은 `null` 또는 `error`다.
- Evidence: `request_count`, `apis`, `destinations[].url`, `etld1`, `external`.

### L3-J-05 — Credential Access

- 설명: 정책상 Credential Field를 DOM API로 찾은 뒤 해당 요소의 `.value`를 읽는
  Source를 식별한다.
- 양성: 식별된 Credential Field의 값 읽기 AST가 1개 이상이다.
- 음성/미확정: 완전한 정책·Source에서 접근이 없으면 `false`; Credential 분류
  정책이나 분석이 불완전하면 `null` 또는 `error`다.
- Evidence: `credential_types`, `fields`, `access_count`.

### L3-J-06 — Credential Exfiltration

- 설명: Credential `.value`에서 시작한 taint가 변수/변환을 거쳐 Network API의
  payload 인자로 전달되고 목적지가 외부인지 확인한다. Source와 Sink가 따로 존재하는
  것만으로는 탐지하지 않는다.
- 양성: 동일 계보의 Credential Source→Network Sink 연결이 있고 목적지 eTLD+1이
  현재 사이트와 다르다.
- 음성/미확정: 완전 분석에서 연결이 없거나 연결된 목적지가 same-site면 `false`;
  Source/Sink만 따로 있거나 목적지/계보가 불명확하면 `null`이다.
- Evidence: `source`, `field_id`, `transformations`, `sink`, `destination`,
  `destination_etld1`, `external`, `source_event_id`, `sink_event_id`.

### L3-J-07 — Dynamic Redirect

- 설명: 정책 Navigation API 호출 또는 URL 대입을 찾아 JavaScript 기반 이동 의도를
  기록한다.
- 양성: `location.replace/assign` 호출 또는 `location.href`/`window.location`
  대입 AST가 1개 이상이다.
- 음성/미확정: 완전한 정책·Source에서 해당 호출/대입이 없으면 `false`; 정책이나
  분석이 불완전하면 `null` 또는 `error`다.
- Evidence: `redirect_count`, `api`, `destination_url`.

### L3-J-08 — Anti-Bot / Headless Detection

- 설명: 자동화·Headless 판별에 사용하는 정책 Browser 속성을 읽는 코드를 찾는다.
  실제 분기나 우회 행동은 필수 조건이 아니다.
- 양성: 정책 속성의 MemberExpression 읽기가 1개 이상이다.
- 음성/미확정: 완전한 정책·Source에서 읽기가 없으면 `false`; 정책이나 분석이
  불완전하면 `null` 또는 `error`다.
- Evidence: `properties`, `check_count`.

### L3-J-09 — Environment-Based Branching

- 설명: J-08 환경 속성이 `if` 또는 삼항 조건에 쓰이고 양쪽 Branch의 정적 행동이
  실제로 다른지 비교한다.
- 양성: 환경 속성이 조건에 참여하고, 정규화된 양쪽 행동이 모두 비교 가능하며 서로
  다르다.
- 음성/미확정: 속성 읽기만 있거나 양쪽 행동이 같으면 `false`; 정규화 정책이나
  분석이 불완전하면 `null` 또는 `error`다.
- Evidence: `properties`, `conditions`, `branch_behaviors`.

## operational-v1 정책값

기본 CLI는 `policies/operational.v1.json`의 다음 값을 사용한다. 이 값은 Analyzer에
하드코딩된 기본값이 아니라 버전 관리되는 정책 입력이다.

| 구분 | 값 |
| --- | --- |
| Credential `type` | `password → password`, `email → email` |
| Credential `autocomplete` | `current-password`, `new-password`, `username`, `email` |
| Credential 식별 토큰 | password: `password`, `passwd`, `passcode`; email: `email`, `e-mail`; username: `username`, `user_name`, `user-id`, `userid`, `login` |
| J-01 실행 API | `eval`, `Function` |
| J-02 Decode API | `atob`, `decodeURIComponent`, `unescape` |
| J-04/J-06 Network API | `fetch`, `navigator.sendBeacon`, `XMLHttpRequest.open` |
| J-07 Redirect API | `location.replace`, `location.assign`, `location.href`, `window.location` |
| J-08/J-09 환경 속성 | `navigator.webdriver`, `navigator.plugins`, `navigator.languages`, `window.chrome` |
| J-09 행동 비교 | 양쪽 Branch의 정적 행동 목록을 canonical JSON으로 정규화해 비교 |

Credential 분류 우선순위는 `type` → `autocomplete` → `id/name/placeholder` 토큰이다.
식별 속성은 대소문자를 무시하고 비문자/밑줄 경계를 정규화한다. 서로 다른 Credential
유형이 동시에 일치해 하나로 확정할 수 없는 필드는 분류하지 않는다.

기본 정책에는 특정 브랜드와 공식 도메인이 없다. 별도 수동 브랜드 정책 또는 버전이
명시된 Wikidata 캐시를 주입하지 않으면 H-05와 H-06은 보통 `detected=null`이다.
이는 “브랜드 불일치 없음”이 아니다.

## 해석 시 주의사항

- H-01/H-02 양성은 로그인·가입 기능의 존재를 뜻할 뿐 피싱 확정이 아니다.
- H-03은 관측용이며 외부 POST 탐지는 H-04가 담당한다.
- H-05/H-06은 최신의 검증된 브랜드 정책 없이는 결론을 내리지 않는다.
- J-01/J-03/J-04/J-07/J-08은 정상 애플리케이션에서도 흔할 수 있으므로 단독 차단
  기준으로 사용하지 않는다.
- J-02/J-06/J-09는 각각 Decode→실행, Credential→외부 Sink, 환경 조건→상이한 행동의
  관계가 확인되어야 하며 개별 이벤트의 단순 동시 존재로 양성화하지 않는다.
- 잘린 HTML/Script에서 발견한 양성 Evidence는 유지할 수 있지만, 발견하지 못한 것을
  근거로 `false`를 반환하지 않는다.
