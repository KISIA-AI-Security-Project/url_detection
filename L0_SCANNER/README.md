# L0 — URL 문자열 분석과 저장

2026-09-23 사용자 검토안의 생산·저장 구조와 2026-09-28 승인한 L0 Context Builder 연결을 반영한 로컬 코드다. 운영 배포와 실제 모델 판단 실험은 포함하지 않는다.

## 입력과 출력

`l0.registry.analyze(url)`은 접속 없이 WHATWG 파싱과 로컬 목록·문자열 비교를 수행한다.

- `raw_evidence`: 원본 URL, 정규화된 URL 구성 요소, PSL 도메인 분해, 파싱 상태와 URL 표준. 쿼리 원문은 parsed.search에 포함된다.
- `observations`: 조건이 존재할 때만 생성하는 0개 이상의 record. 각 객체는 정확히 `검사`, `관찰`, `판단에 쓸 점` 세 필드다.
- `errors`: 분석 중 발생한 오류. 양성 record나 음성 record로 바꾸지 않는다.
- `analysis_execution`: 실행 여부, 등록 검사 수, 실제 record 수.
- `reference_versions`: 사용한 참조 목록 버전.
- `judgment_guidance`: DGA·타이포스쿼팅의 후속 LLM 판단 안내. 별도 휴리스틱 record는 없으며 Builder에서 한 번 전달한다.
- `producer_contract`: `url-observations-3`.

성공한 실행에서 관찰 조건이 없으면 `observations: []`이며 분석은 완료 상태다. 무효/빈 입력은 raw를 남기고 분석을 수행하지 않는다. 한 검사나 쿼리 값의 실패는 다른 값의 기록을 지우지 않는다.

## 남기는 10종

| 검사 | 기록 조건 |
|---|---|
| IP_호스트 | WHATWG 호스트가 IPv4/IPv6 |
| 피싱_빈발_TLD_목록_일치 | TLD가 로컬 참조 목록에 일치 |
| 무료_발급_도메인 | 제공자 목록 일치 + 하위 주소 존재 |
| 호스트_단어_분리 | 도메인/서브도메인 라벨을 - 또는 _로 두 개 이상 비어 있지 않은 부분으로 분리 |
| IDN_문자_변환 | IDN을 Unicode로 풀고 비교용 문자로 변환한 결과가 달라짐 |
| 이중_확장자 | 마지막 두 확장자가 설정된 DECEPTIVE/DANGEROUS 조합 |
| 단축_서비스_목록_일치 | 호스트 또는 등록 도메인이 참조 목록에 일치 |
| 쿼리의_외부_주소 | URL로 해석되는 쿼리 값의 대상이 다른 등록 도메인 또는 다른 IP |
| 접속_호스트_교란 | 파싱된 username 존재 |
| 서브도메인_구조_이상 | 서브도메인 라벨이 PSL suffix 항목과 일치 |

호스트 분리는 브랜드 목록을 사용하지 않는다. xn-- 인코딩 접두부의 하이픈을 단어 구분자로 오인하지 않도록 IDN 라벨을 먼저 푼다. IDN record의 실제 접속 호스트는 raw의 ASCII 호스트와 동일한 호스트를 Unicode로 표시한 값이고, 비교용 표기는 코드의 문자 변환 결과다. 브랜드/사칭 여부는 코드가 정하지 않는다.

쿼리 외부 주소는 항목명 목록에 의존하지 않는다. 명시적 scheme 또는 // 형태의 값을 URL 파서로 해석하고 호스트를 비교한다. 같은 호스트/등록 도메인, 일반 텍스트, 상대 경로에는 record를 만들지 않는다. 외부 주소가 발견돼도 자동 이동/실행을 주장하지 않는다.

같은 쿼리 이름이 반복되면 값마다 기록한다. `값_순번`은 같은 이름의 값 배열에서 0부터 시작한다. 호스트의 반복 라벨과 서브도메인 suffix도 위치별로 보존한다. 참조 목록 불일치는 안전 판정이 아니다.

## 제거한 8종

비표준_포트, 타이포스쿼팅, 파일_다운로드, XSS, DGA_패턴_의심, 긴_URL, Base64_인코딩, 비표준_프로토콜의 실행 로직과 전용 자료를 제거했다. DGA/타이포스쿼팅은 안내만 보존한다. 실제 다운로드는 후속 관찰 대상으로 남기며 이중_확장자는 유지한다.

무료 발급 제공자 목록에는 onrender.com, wordpress.com, blogspot.com, azurewebsites.net, appspot.com, run.app 6개를 추가했다. 총 32개이며 서비스 루트 자체에는 record를 만들지 않는다.

## raw 구조

`raw_url`은 입력 그대로, `parsed.href`는 파서가 정규화한 URL이다. 사용자 요청으로 raw의 `list_version`을 제거하고 최상위 `url_standard`만 남겼다.

- `stage`, `raw_url`, `parse_status`
- `url_standard`: `WHATWG`
- `parsed`: href, protocol, username, password, hostname, port, pathname, search, hash, host_type
- `query_status`, `query_errors`: absent/complete/partial과 항목별 파싱 오류
- `extracted`: subdomain, domain, suffix, registered_domain

PSL private suffix는 기존과 같이 제외한다. 따라서 github.io 등의 서비스 제공자 도메인을 등록 도메인 필드에서 비교한다. 분해한 query 객체는 record 검사용 내부 입력으로만 사용하며 raw에 중복 저장하지 않는다. 원래 쿼리 문자열과 순서는 raw_url/parsed.search에 남는다.

`??a=1`에서 두 번째 ?는 항목명의 일부다. 첫 구분자 하나만 제거하도록 기존 lstrip 오류를 수정했다.

## 저장 경계

공통 record의 L0 저장 계약은 `l0-observations-1`이다. `signals`에 compact record들을 그대로 저장하고 실행 상태·오류·raw hash·목록 버전은 공통 위치에 한 번 남긴다. 구형 `analysis_records`와 `url-evaluations-2` 저장 자료의 판독은 유지한다.

Builder는 새 compact 계약을 별도 경로로 읽는다. URL 기본 정보와 모든 관찰을 전달하며, 같은 검사와 안내를 묶어도 발생별 값·위치·순번은 보존한다. 반복되는 기본 호스트·등록 도메인은 공통 대상에서 한 번 제공한다. L0 상태·오류·해시·목록 버전은 모델 문서에서 제외하고 record/audit에 남긴다.

L0 선택 로직은 `evidence_pipeline/l0_context.py`에 두며 공통 Builder는 이를 연결한다. L0 / L1 / L23은 각각 보완한다는 사용자 지시에 따라, 이번 작업은 다른 계층의 Builder 규칙이나 공통 전송·Result 계약을 변경하지 않는다.

DGA·타이포스쿼팅 안내는 항상 포함한다. 단축 서비스·무료 발급 도메인·이중 확장자 안내는 각각 해당 종류의 record가 없을 때만 추가한다. 관찰 부재를 목록 불일치나 안전으로 바꾸지 않으며, TLD 통계 추측 안내를 만들지 않는다.

검증 범위는 생산 → raw/record 직렬화 → 저장 재조회 → Builder → Judgment v2 문서 → 모형 Messages 요청이다. 실제 모델 판단 품질·AWS 운영 적용 검증과 구분한다.
