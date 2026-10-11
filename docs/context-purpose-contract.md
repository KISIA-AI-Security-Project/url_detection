# 목표와 검토 범위

> 2026-10-08 로컬 보완: L3가 직접 연결된 fetch 응답 처리와 이벤트 콜백 문맥을 `request-context-1`로 생산하고 J04 record에 보존한다. Builder는 등록 이벤트·조건의 선택 대상·같은 블록의 이벤트 제어·응답 text 값의 document.write 사용 관계를 선별해 모델 본문과 직접 연결 공개 사실에 전달한다. 원문 길이로 전체 스크립트를 인용하지 않는다. 재할당·shadowing·다른 함수/분기·중간 변환·with 범위는 지원 조건을 벗어나면 연결하지 않는다. 실제 실행과 응답 내용을 확인한 것은 아니다. 빈 공개 항목 목록은 모델 본문에서 생략하고 내부 매핑에 남긴다. 저장 원문 재생과 실제 Fast 저장→모형 Messages→공개 결과의 범위는 [보완 기록](../../../remediation-20261008/purpose-and-user-options-1/README.md)을 따른다. 이 문단은 로컬 구현이며 운영 적용이나 실제 판정 품질 완료를 뜻하지 않는다.

> 2026-10-06 현재 적용: 준비된 EC2 경로와 Context20·Judgment26·L23:19·Gate2/Result4를 사용한다. 순수 JavaScript 객체·배열 콘텐츠의 정적 선언과 같은 객체의 문구·주소 관계를 추가하고, 공개 항목의 쉬운 설명과 기존 항목 이름 연결을 적용했다. 판정·요약·이유는 Sonnet 5.5가 작성하며 코드가 재판정하지 않는다. 실제 로그인 Front의 새 URL 5건에서 raw → record → Builder → 실제 Messages → 공개 결과를 대조했다. 한 의심 응답의 근거 없는 정상 가설·공개 공백 설명과 일부 중첩 JS 분석 한계는 남아 있다. 아래 날짜별 문구는 각 당시의 적용 범위다. [현재 Front 계약](fast-result-front.md)과 [실제 검토](../../../remediation-20261006/fast-verdict-review/five-front-runs-v5-independent-review.md)를 따른다.

> 2026-10-05 후속 I/O·GC 적용: URL·도메인·라이브러리별 예외 없이 외부 JS 조회 병렬화, 한 요청의 TLS 설정 중복 제거와 임시 AST 분석 중 순환 GC의 정리 시점을 조정했다. EC2 준비된 컨테이너와 Lambda L23:18의 실제 경로에 적용했으며 Judgment23·Context17·Sonnet 5.5/high/8192는 유지한다. 7개 서로 다른 URL의 9개 확보 입력을 같은 AWS 이미지에서 36회 교차 재생했고, 배포 후 Python 동시 두 건·Mozilla·Wikipedia·첫 PostgreSQL 요청까지 실제 모델·공개 GET을 보존했다. 직전 동시 Python의 모델 요청 외 HTTP는 EC2 7.275→4.816초, Lambda 10.871→8.098초였다. 작은 JS 계산의 36~42ms 증가, 일부 모델 항목명 미연결과 R10 설명 문제는 남는다. [최신 실제 증거·책임·한계](../../../remediation-20261005/new-url-validation/REPAIR-REPORT.md)를 따른다. 기능 보존 비교를 모든 URL의 지연·판정 정확성 보장으로 확대하지 않는다.

> 2026-10-05 새 URL 재검증: 앞선 간단한 페이지의 시간만으로 전체 성능 개선을 설명하지 않는다. Python/GitHub/Mozilla를 실제로 요청해 HTML 공유 메타데이터 순서 비교 결함, EC2 프로세스 전달의 버퍼 없는 읽기, Esprima AST 변환 병목을 확인하고 수정했다. 첫 수정 후 Python의 모델 요청 외 HTTP 시간은 11.036→6.359초였다. GitHub는 실제 판정까지 완료했고 Mozilla는 별도의 모델 응답 형식 오류를 남겼다. 후속 Judgment22는 기존 판정 기준·검사 코드를 유지한 채 JSON 키 위치만 세 문장으로 명확히 했다. [새 URL 수정·실제 증거와 남은 문제](../../../remediation-20261005/new-url-validation/REPAIR-REPORT.md)를 현재 근거로 읽는다. 아래 시간은 각 당시 입력의 관측값이며 일반적인 지연 보장이 아니다.

> 2026-10-05 성능 개선·실제 API 연결: 모델 종류·지시·판정 책임과 Builder 선별 계약을 유지하면서, 준비된 EC2 컨테이너·Lambda fallback, 작업 안의 확정 bytes 재사용, 독립 S3 I/O 병렬화와 일반 API의 qualified 버전 연결을 적용했다. 실제 dev API 신규 2건·동일 ID 재분석 1건의 raw → record → 최종 Messages → 공개 결과를 보존하고 이전/개선 코드로 대조했다. 모델 외 전체 대기는 1.643–2.767초, 판정 전 공통 구간은 0.912–1.872초였다. [실제 시간·책임](../../../remediation-20261005/performance-round4/timing-analysis/actual/FINDINGS.md)과 [Front 연동](fast-result-front.md)을 따른다. 아래 날짜별 배포 미실행 문구는 당시 기록이다. 이번 성능 개선은 기존 R10 모델 설명 문제의 해결이나 mock Front의 API 연결 완료를 뜻하지 않는다.

> 2026-10-02 빠른 분석 통합: 사용자가 Notion의 전체 모델 지시·대표 예시·UNKNOWN 빈 reasons를 승인하고 구현을 요청했다. `build_fast_context`는 기존 선별 지점에서 L0–L3 모델 본문·공개 사실·내부 매핑을 함께 만든다. `fast-result-1`을 활성화한 AWS Context/Judgment/Result 경로는 승인 prompt, 같은 문서의 항목명 연결, 공개 allowlist, 실패 상태와 판정의 분리, 내부 심층 handoff를 사용한다. 기존 기본 경로는 별도이며 운영 배포를 자동 전환하지 않는다. 현재 구현과 동일 입력 증거는 [구현 기록](../../../remediation-20261002/fast-result-implementation/README.md), 사용법은 [Front 연동](fast-result-front.md)과 [AWS 후보 생성](fast-result-aws-deployment.md)을 따른다. 실제 모델 판단 품질과 AWS 운영 적용은 별도 확인 대상이다.

> 2026-10-02 JavaScript Builder 후보: 사용자의 “뼈대·실제 입력/결과를 함께 풀어 JS 전체를 완성한 다음 검토” 지시에 따라 J01~J09의 관계를 선별하는 JS 문서와 HTML+JS 통합 문서를 구현했다. 동적 API·문자열 변환, 스크립트 삽입, 입력 읽기와 요청 인자, 환경 조건과 이동을 같은 원문·native·record에서 구성한다. 생성/호출·조건·자료 미확보·제한된 값 해석을 실제 실행과 구별한다. 공개 진입점은 build_javascript_text_context와 build_text_context의 명시적 html_javascript 범위다. 실제 Messages 직전에 입력에서 본문·blocks·mapping·audit를 재구성한다. 이 항목은 구현 후보의 범위를 설명하며 사용자의 최종 본문 승인, 모델 판단 품질 또는 운영 적용을 뜻하지 않는다. [JS 정보 지도·동일 입력 최종 문서·독립 검토](../../../remediation-20261002/javascript-context/README.md)를 확인한다. 기존 HTML 단독 v2, 전체 L3 기본 경로의 차단, 운영 handler와 응답 계약은 별도의 기존 범위를 유지한다.

> 2026-10-02 HTML 브랜드 표시 보완: 현재 HTML 본문은 `l3-html-text-2`이다. 브랜드를 주소 대조에 선택된 대상으로 표현하고, 생산 결과가 기록한 선택 근거의 위치를 읽기 쉬운 이름으로 전달한다. `brand_identification_confidence`는 검증된 정확도가 아니므로 본문에서 제외하며, H05/H06 각각의 native·record·audit 값과 제외 이유를 보존한다. 확신 등급만 다른 동일 근거는 함께 표시하고 양쪽 원본 포인터를 연결한다. 근거 위치·자료 출처·브랜드 항목 ID가 다르면 별도 대조로 유지한다. HTML 원문에 포함된 `high`, `low`, `confidence` 문자열은 삭제하지 않는다. 현재 전송 경계는 v1 본문을 거부하며 당시 소스와 증거는 보존한다. [v2 변경과 같은 입력의 최종 문서](../../../remediation-20261002/html-brand-context-v2/README.md)를 확인한다.

> 2026-10-01 HTML 구현: 사용자의 HTML 전체 완성·서브에이전트 검토 지시에 따라 `l3-html-text-1` 입력 API를 추가했다. H01~H08과 현재 구조화된 주변 HTML을 같은 raw/record에서 직접 선별하고, 관계·차이·관측 한계를 주체별로 구성한다. `build_html_text_context` 및 `build_text_context(..., l3_scope='html')`을 제공하며 실제 Messages 준비 시 같은 입력의 최종 본문·블록·근거 대응을 재검증한다. JavaScript는 명시 HTML 문서 밖이고 전체 원본·record·audit에 보존된다. 기본 전체 L3 경로의 미검토 gate, 운영 기본 handler, 응답 검증·프론트 연결 경계는 유지한다. [HTML 전달 계약·같은 입력 결과·독립 검토](../../../remediation-20261001/html-context/README.md)를 확인한다. 아래 9월 29일 문구의 L3 미구현 범위는 이번 HTML 추가에 한해 갱신된다.

> 2026-09-29 최신 설계 합의: raw·record와 내부 근거 대응은 JSON으로 보존하고, 모델 본문은 계층별 **제목·고정 항목·짧은 설명문**으로 구성한 뒤 L0·L1·L23을 통합한다. 기존 E-ID/JSON 응답 검증은 이 방향을 제한하는 요구가 아니며 후속 연결에서 맞춘다. 승인된 L0·L1·L2 선별을 구획 텍스트로 바꾸는 `layer-text-1` 렌더러와 그 본문을 그대로 Messages로 전송하는 입력용 API를 구현했다. L3 세부 선별, 조정 계층의 활동 요약 표시, 응답 검증·프론트 근거 연결은 아직 별도 작업이며 기존 AWS Judgment handler의 기본 경로를 전환한 것은 아니다. [현재 구현과 한계](layer-text-context.md)를 확인한다. 아래 JSON/E-ID 설명은 내부 선별 및 기존 경로의 설명이며 새 본문의 의무 형식이 아니다. 세부 승인 범위는 [최신 통합 인계](../../../../docs/L0-L1-L23-Builder-통합인계-20260929.md)를 따른다. 기존 L23 작업의 최신 record별 승인은 유지하고, 형식별 모델 비교실험은 필수 단계로 추가하지 않는다.

> 2026-09-28 L0 변경: 아래의 18종 `evaluations` 및 반복 assessment 설명은 과거 v2 계약이다. 새 L0는 10종 조건의 positive-only `observations`를 생산하며, 저장 record의 `signals` 항목은 `{검사, 관찰, 판단에 쓸 점}` 그대로다. 생산 계약은 `url-observations-3`, 저장 계약은 `l0-observations-1`이다. 9월 23일 승인 범위는 raw/record 저장까지였고, 9월 28일 사용자가 L0 Builder 연결을 승인했다. 현재 전달 계약은 아래 L0 절과 [L0 README](../L0_SCANNER/README.md)를 따른다. 실제 모델 판단 실험·배포는 수행하지 않는다.

접속 전 URL 판단에 필요한 사실·관계·관측 한계를 모델이 함께 읽게 한다. URL verdict는 Judgment의 책임이다. 기술 규칙 일치, 목록 일치, 문자열 유사성, 정적 Source→Sink 관계는 악성·사칭·실행·소유권을 확정하지 않는다.

이번 변경은 로컬 후보이다. 배포된 AWS 기준선과 저장 원본은 보존한다. 새 수집·모델 호출·AWS/Notion/GitHub 쓰기를 수행하지 않는다. 테스트의 모형 전송은 모델 품질이나 실제 토큰 수의 증거가 아니다.

## 생산 → 공통 record → Builder

| 경계 | 책임 | 현재 구현 |
|---|---|---|
| L0 | URL 파싱과 조건에 해당하는 관찰 생산; 상태·오류는 별도 보존 | `l0.registry.analyze`의 `observations`; 저장 `signals`와 동일한 세 필드 |
| L1 | 조회 대상·실제 응답·부분 실패·실행 중단·미시작 기록 | native `detail`, `observation`, `query_lifecycle`; 전체 IP-ASN 실패도 대상별 원인 보존 |
| L2 | 확보한 HTTP/TLS/CT와 분석 결과의 구분 | 수집 위치에서 발생 ID/대상/영향 축을 기록; 분석 예외는 별도 analysis occurrence |
| L3 | 원문·파싱·정적 관계·정책 조건과 미확정 생산 | 복사 전에 발생 ID를 부여; 복수 Source→Sink/Decode→실행/이동 이벤트 보존 |
| 공통 record | 계층별 native 상태를 공통 축으로 정규화하고 native 세부 결과·관계를 보존 | `records.build_record`, `record_contract.validate_record`; native 상세를 다른 계층 규칙으로 재판정하지 않음 |
| Builder | 제공된 사실·관계를 문서로 조직, 동일 값 공유, 짧은 인용 연결, 감사 정보 분리 | `context_source` → `model_context`; 오류의 원인·단계·미수행 부분을 추정하지 않음 |
| Gateway | 실제 선택된 문서의 인용 스키마, 전송과 응답 검증 | `prepare_context` → `judgment-request.json` → 동일 E-ID 검증 |

## C08 모델 전달 제외와 C03 관계 유지 — 2026-09-29

현재 전달 버전은 `decision-evidence-11`이다. C08의 와일드카드 존재 여부, 전체
와일드카드 목록, SAN 항목 수는 raw·record·audit에 유지하고 모델의 별도 검사 행에서
제외한다. 추가 통계 검증은 계획하지 않는다. C03이 실제로 대조한 호스트와 일치 이름,
불일치 시 필요한 인증서 이름 목록은 기존 선택대로 유지한다. C03에서 사용되지 않은
다른 와일드카드 이름을 C08을 통해 다시 나열하지 않는다.

`l2_wildcard_context.C08Selection`은 C08 전용 분석 한계를 생략하며, C07/C08만
공유하는 분석 원인도 audit에 남긴다. 다른 보이는 검사와 공유하는 원인은 해당 근거의
참조와 함께 유지한다. 공통 TLS 수집 실패는 관련 C07/C08 행을 생략해도 유지한다.
최종 Builder·Messages 양쪽에서 C08 검사·wildcard_names·san_count 재유입을 검사하되
C03의 일치 이름과 SAN 목록에 포함된 와일드카드 문자열을 금지하지 않는다.
과거 v2–v10 문서는 당시 계약으로 읽는다. 생산자의 실행 코드와 저장 결과는 유지한다.

## C07 모델 전달 제외 — 2026-09-29

이 선택의 도입 버전은 `decision-evidence-10`이다. 사용자는 실제 협상된 TLS 버전의
악성/정상 구별 가치가 확인되지 않았으므로 C07을 모델 전달에서 제외하도록 승인했다.
수집기·분석 결과·raw·record는 유지한다. 코드 주석의 구형 TLS와 피싱 운영을
직접 연결하던 설명만 바로잡는다.

`l2_tls_version_context.C07Selection`은 true/false/null에 관계없이 C07 검사 행과
C07 전용 분석 한계를 모델에서 생략한다. 원래 값과 원인은 audit의 source_context에,
선택 이유는 model_omissions에 남긴다. 다른 검사와 공유하는 원인과 TLS 수집 실패는
유지하며, 생략된 C07을 가리키는 원인 참조만 제거한다. C07 별도 안내나 빈 행을 만들지 않는다.
Builder와 최종 Messages 양쪽에서 C07 검사·버전 필드의 재유입을 검사한다.
과거 v2–v9 문서는 당시 계약으로 읽는다. 이 변경은 모델의 판단 성능 검증이 아니다.

## C06 경과일 측정과 모델 전달 선택 — 2026-09-29

이 선택의 도입 버전은 `decision-evidence-9`다. 사용자가 승인한 C06 표시는
`인증서 CT 기록 시각`, `해당 시각 이후 경과: 검사 당시 N일`, `출처` 세 줄이다.
출처는 수집 자료에 따라 `인증서에 포함된 SCT` 또는 `crt.sh 조회`로 표시한다.
내장 SCT를 우선하고 없으면 crt.sh를 조회하는 기존 수집 방식은 유지한다.
여러 시각 중 수집기가 선택한 가장 이른 시각을 쓰며, 세계 최초 관측 시각으로
확대해 설명하거나 SCT 서명·로그 포함 증명 검증을 추가하지 않는다.

새 C06 생산 결과는 `result_kind: measurement`와 `measurement_state`를 제공한다.
근거에는 `first_seen`, `age_days`, `measured_at`, `source`를 보존하며, 고정 30일
기준과 `fresh`/`detected`는 제거한다. 기록 시각 이후 경과를 정수 일수로 계산하고
미래 시각의 음수도 보존한다. 자료 부재나 분석 실패는 기록된 원인과 연결한다.

`l2_ct_context.C06Selection`은 저장된 시각·경과일·출처를 선택한다. Builder가
현재 시각이나 스캔 종료 시각으로 재계산하지 않는다. 측정 기준 시각과 내부 상태는
record/audit에 두고 모델에는 합의한 세 표시값과 같은 인증서의 참조만 전달한다.
과거 bool/fresh record도 원래 저장된 시각과 경과일을 쓴다. 과거의 계산 기준
시각을 새로 만들지 않으며, 출처는 같은 입력의 raw CT 자료에서 보완할 수 있다.
과거 `fresh`/`detected`는 원본·record/audit에 보존하고 모델에서 생략한다.

값이 없으면 CT 조회의 실제 실패 이유, 빈 조회 응답, 시각 없는 조회 항목,
인증서 미확보를 저장된 자료에 맞게 구분한다. 동일 TLS 수집 한계를 반복하지 않는다.
HTTP 응답 실패만으로 확보한 CT 결과를 생략하지 않는다. 서로 다른 오류 발생은
각각 남긴다. record와 같은 입력의 raw 시각·출처가 충돌하면 구성 오류로 처리한다.
Builder와 최종 Messages 문서에서 내부 필드·최근 여부 판정의 재유입을 검사한다.
이전 v2–v8 문서는 당시 계약으로 읽는다. 동일 입력 검증은 실제 CT 서비스 응답,
모델 판단 품질 또는 운영 적용의 검증과 구분한다.

## C05 모델 전달 선택 — 2026-09-29

사용자가 승인한 제목은 `서버 인증서 검증`이다. 이 선택의 도입 버전은
`decision-evidence-8`이며 `l2_chain_context.C05Selection`이 C05 record의
`evidence.valid`를 선택한다. `detected`는 검증 실패 탐지값이므로 이를 성공 여부로
읽지 않는다. 생산자, TLS 검증 방식, 원본·record 저장 계약은 바꾸지 않는다.

- true는 `스캐너가 신뢰하도록 설정한 인증서를 기준으로, 서버 인증서부터 발급기관으로
  이어지는 서명 관계와 TLS 인증서 유효성 검사를 통과함.`으로 표시한다.
- false는 `실패`와 실제 기록된 검증 실패 사유 원문을 표시한다. 사유가 없는 과거
  결과는 `실패 사유 미기록`으로 구분하며, 모든 실패를 발급기관 불신으로 해석하지 않는다.
- null에서는 검증 결과 문장을 만들지 않는다. 실제 TLS 미시도·연결 실패는 공통 한계로
  유지한다. C05 분석 예외는 원문 이유를 보존하고, 이유가 기록되지 않았으면 그 사실만
  표시한다. 인증서가 없다는 이유로 검증 실패를 null로 바꾸지 않는다.

이 결과는 기본 신뢰 설정을 사용한 첫 TLS 접속의 검증 결과다. 검증 실패 후에는
인증서 수집을 위한 별도 접속이 이뤄질 수 있으므로, 실패 결과에 이 경계를 붙인다.
두 접속에서 받은 인증서가 동일하다고 Builder가 추정하지 않는다. 별도 재접속 실패도
보존한다. 이름 대조는 C03 결과이고 정확한 검증 시각은 생산자가 저장하지 않으므로
C01/C02 시각으로 대신하지 않는다. 사이트 안전성·운영자 신뢰를 확정하지 않는다.

알려진 결과는 같은 TLS 관측 정보에 한 번 붙인다. `chain_valid` 중복값, C05 일반
검사 행, 체인 깊이는 모델에서 생략하고 record/audit에서 추적한다. 체인 깊이는
내보낸 인증서 목록의 개수이며 검증 성공 여부와 별개다. raw가 없는 과거 record에
결과가 남아 있으면 결과를 보존하되 TLS 접속 호스트를 만들어 넣지 않는다.
v8의 공통 TLS 정보에는 결과 유무와 관계없이 raw `chain_valid`를 싣지 않는다.
C05 record 자체가 없는 경우에도 raw bool로 새 검사 결과를 만들지 않고 audit에 보존한다.
제공된 raw와 record의 결과·오류가 충돌하거나 known 결과에 C05 분석 실패가 함께
기록되면 구성 오류로 거부한다. Builder와 최종 Messages 양쪽에서 재유입을 검사한다.
이전 v2–v7 문서는 당시 계약으로 읽는다. 동일 입력 원본부터 모의 Messages까지의
검증은 실제 모델 판단 품질이나 배포의 증거가 아니다.

## H09 모델 전달 선택 — 2026-09-28

H09가 HTTPS→HTTP 이동 지시를 관측한 경우에만 H01의 경로 근거 아래에
`HTTPS→HTTP 이동 지시: 관측됨`을 한 번 붙인다. 목적지 응답 수신 여부와 별개이며,
악성·피싱 빈도·공격 의도는 이 문구로 주장하지 않는다. H09의 별도 check 행과
첫 출발/도착 URL, 강등/상향 횟수는 모델에 반복하지 않는다. false/null일 때는
H09 문구를 생략한다. 이 선택은 `l2_context.H09Selection`이 담당한다.

H09 전체 결과와 H09만 관련된 분석 실패는 record 및 audit의 source_context에
보존한다. 다른 검사와 공유하는 HTTP 수집 한계는 유지한다. true인 H09를 붙일
H01 경로가 없거나 첫 강등 주소 쌍이 그 경로와 맞지 않으면 구성 오류로 처리하여
관측을 조용히 버리지 않는다. 새 Builder 출력의 선별 검사와 최종 Messages 검사로
H09 상세값의 재유입을 확인한다. H09 선택은 `decision-evidence-3`부터 적용하며,
Judgment v2도 문서 버전을 전달받아 강등이 없는 문서까지 선별을 검사한다.
과거 `decision-evidence-2` 저장 모델 문서는 기존 형태로 읽을 수 있다.

## C01 생산 결과 변경 — 2026-09-28

사용자가 C01의 고정 30일 기준을 지적하여 최근 여부 판정을 제거했다. 새 C01은
`result_kind: measurement`와 생산자가 기록한 `measurement_state`를 제공하고,
근거에 인증서 유효 시작 시각(`not_before`), 계산 기준 시각(`measured_at`), 정수
경과일(`age_days`)을 보존한다. 미래 시작도 음수 값으로 남긴다. `fresh` 및 `detected`는 없다.
record는 값을 다시 계산하거나 새로운 기준으로 분류하지 않고, 측정 가능은
`observed`/`relationship_only`, 자료 미확보·분석 실패는 기록된 원인과 `unresolved`로 연결한다.
과거 bool/fresh C01 기록은 변경하지 않는다. C06의 CT 기준도 이번 범위 밖이다.
생산 및 저장 검증과 아래의 Builder 선택 검증은 실제 모델 판단 품질의 증거가 아니다.

## C01 모델 전달 선택 — 2026-09-28

사용자가 승인한 표시는 `인증서 유효기간 시작 후 경과: 15일` 및
`계산 기준 시각: measured_at`이다. `l2_context.C01Selection`이 새 measurement
record의 경과일과 측정시각을 그대로 선택한다. Builder에서 현재 시각이나 스캔
종료 시각으로 경과일을 다시 계산하지 않는다. 음수는 `-3일 (유효기간 시작 전)`처럼
보존하며 정확히 72시간 뒤라고 바꾸지 않는다. 인증서의 발급일·도메인 나이·최근 여부를
판정하지 않는다. `certificate_ref`는 같은 입력의 TLS 관측 대상을 연결한다.

유효 시작 시각 `not_before`와 상태·assessment 등 내부 포장은 record 및 audit에
보존한다. 모델에는 `certificate_age` 항목의 두 표시값과 인증서 참조만 전달한다.
HTTP 응답 미확보 여부로 이 측정값을 생략하지 않는다. 인증서 자체가 없으면 C01 행을
생략하고 기존 TLS 수집 한계를 유지한다. 이때 중복되는 C01 전용 시작시각 미확보 원인은
audit에 남긴다. TLS 원인이 기록되지 않았으면 수집 자료에 인증서가 없다는 사실만
공통 한계로 표시한다. 인증서는 있으나 시작값이 없거나 분석 예외가 발생하면 C01 고유
한계를 한 번 표시하고, 분석 예외의 기록된 이유를 보존한다.

과거 bool/fresh C01에는 새 측정 계약과 `measured_at`이 없으므로 새 두 줄을 만들지
않는다. 과거 C01 원본은 record/audit에, 선별 이유는 model_omissions에 남긴다.
`decision-evidence-4`부터 Builder 및 최종 Judgment v2 문서에서 C01 내부
포장·fresh 판정·원문 날짜의 재유입을 검사한다. 이전 v2/v3 저장 모델 문서는 당시
형태로 읽을 수 있다. 다른 L2 항목의 새 선별은 이 C01 변경에 포함하지 않는다.

## C02 모델 전달 선택 — 2026-09-28

사용자가 승인한 표시는 `인증서 유효기간 상태` 한 줄이다. 생산자가 기록한
`valid`는 `검사 당시 유효기간 내`, `expired`는 `검사 당시 만료됨`, `not_valid`는
`검사 당시 유효기간 시작 전`으로 옮긴다. `l2_context.C02Selection`이 같은 입력의
TLS 인증서에 `certificate_ref`로 연결한다. C01과 같은 인증서의 결과로 읽으며,
Builder에서 현재 시각으로 재검사하거나 C01 계산 시각을 C02 시각으로 대신하지 않는다.
현재 C02 생산자는 정확한 비교 시각을 보존하지 않는다. 이번 변경은 생산자를 바꾸지 않는다.

시작·만료 시각, 원래 상태, detected 및 record 내부 포장은 record/audit에 보존하고
모델 결과 행에는 승인된 상태 문구와 인증서 연결만 남긴다. 상태와 detected가 서로
충돌하거나 record 날짜와 raw 인증서가 다르면 구성 오류로 처리한다.

결과가 없으면 C02 상태 행을 만들지 않는다. 실제 기록된 TLS 미시도·수집 실패는
공통 관측 한계로 유지하고 같은 발생을 반복하지 않는다. C02 고유 분석 예외는
`인증서 유효기간 검사 실패`와 기록된 이유를 한 번 전달한다. record 자체가 사유
미기록으로 남겼으면 그 사실만 표시하며, 날짜 부재를 임의의 수집 실패로 해석하지 않는다.
다만 raw가 인증서 자체의 부재를 명시하면 C02의 사유 미기록 설명은 audit에 남기고,
공통 TLS 관측 한계로 한 번 전달한다. C01이 같은 부재를 이미 표현하면 이를 재사용한다.
raw 자체가 없을 때는 인증서 부재를 추정하지 않는다.
생략된 C02를 가리키는 빈 검사 참조는 모델에서 제거한다. 발생이 다른 원인들은 합치지 않는다.

`decision-evidence-5`부터 Builder와 최종 Judgment v2 문서에서 C02 내부
포장, 날짜, 임의 시각 및 불명확한 상태 문구 재유입을 검사한다. 이전 v2/v3/v4 저장
모델 문서는 당시 계약으로 읽는다. 동일 입력의 raw/native → 저장 record 재조회 →
Builder → 최종 Messages 문서를 대조하며, 이 검증은 실제 모델 판단 품질의 증거가 아니다.

## C03 모델 전달 선택 — 2026-09-29

사용자는 같은 인증서 정보에서 호스트명과 이름 대조 결과를 한 번만 전달하도록 승인했다.
`l2_context.C03Selection`은 C03 별도 check 행을 생략하고 기존 TLS 인증서 정보에
`인증서 이름 대조`를 붙인다. 일치/불일치와 비교 방식은 record의 matched 및
comparison_scope를 그대로 옮기며, 이름을 다시 비교하거나 CN을 파싱하지 않는다.
C01/C02의 certificate_ref는 이 동일한 인증서 정보를 계속 가리킨다.

SAN 일치이면 `일치 (SAN 기준)`만 남긴다. matched_name이 조회 호스트와 문자열상
다르면 `일치한 인증서 이름`을 추가한다. 와일드카드·대소문자·국제화 이름 등의
변환을 Builder가 다시 판단하지 않는다. 불일치이면 `불일치 (SAN 기준)`과 raw에
실제로 기록된 san_dns/san_ip를 각각 DNS 이름·IP 주소로 표시한다. 이는 인증서에
기록된 목록이며 분석기가 실제로 고른 비교 후보 목록이라고 주장하지 않는다.
양쪽 목록이 명시적으로 비어 있을 때만 기록된 DNS/IP 이름이 없다고 표시한다.

CN 보완 대조는 `일치/불일치 (SAN 없이 CN으로 보완 대조)`로 구분하고 CN을 새로
추출하지 않는다. 과거 SAN 유형 미기록 비교는 그 한계를 결과 문구에 함께 남긴다.
과거 결과에 대조 방식 자체가 없으면 일치/불일치는 보존하되 방식 미기록이라고 표시한다.
결과가 없으면 상태 문구를 만들지 않는다. 실제 TLS 미시도·실패는 공통 원인으로,
C03 분석 예외는 원문 사유와 함께 한 번 전달한다. 유형 미기록으로 대조 결과가 없는
경우는 해당 scope를 관측 한계로 남긴다. 명시된 인증서 부재는 C01/C02와 공통으로
한 번 표시하고, raw 자체가 없으면 인증서 부재를 추정하지 않는다.

원본 SAN·CN·검사값과 내부 포장은 record/audit에 보존한다. 모델의 기존 공통
hostname_match/matched_name/전체 SAN 필드와 C03 check 행의 중복을 제거한다.
별도 C03를 가리키는 원인 참조는 정리하고, 선택된 관계는 공통 인증서 근거에 연결한다.
새 문서 버전은 `decision-evidence-6`이며 Builder와 최종 Judgment v2 문서 모두에서
중복 검사·불필요한 이름 목록·잘못된 상태 표현 재유입을 검사한다. 이전 v2-v5 문서는
당시 계약으로 읽을 수 있다. 검증은 동일 raw/native/저장 record부터 모의 Messages까지이며,
실제 모델 판단 품질·배포·운영 검증과 구분한다.

## L2 설명 보완 및 HTTP/C04 선택 — 2026-09-29

사용자는 표현 점검 결과를 모두 보완하도록 승인했다. 현재 출력은
`decision-evidence-7`이다. 앞 절의 v3–v6 선택 중 아래에 명시된 표시를 갱신하며,
이전 버전으로 저장된 모델 문서는 당시 계약으로 읽는다.

- `l2_http_context.HTTPSelection`은 H01–H08의 record 포장을 전용 사실로 바꾼다.
  HTTP 경로에는 각 주소를 순서대로 한 번씩 적고, 각 응답 코드와 다음 주소로의
  이동 지시를 연결한다. 같은 주소의 재등장은 별도 발생으로 남는다. 마지막 목적지의
  응답 실패는 앞서 받은 이동 지시를 지우지 않는다. Location 없는 302는 응답을 받은
  상태와 경로 미완료를 함께 표시한다. 첫 응답 미확보를 이동 없음으로 바꾸지 않는다.
- H02는 `관측된 이동 경로에서 변경 있음/없음`이라는 등록 도메인 관계를 유지한다.
  H03의 IP 이동 지시와 H04의 단축 서비스 목록 일치는 경로의 해당 위치에 연결한다.
  출발 URL의 목록 일치는 HTTP 실패 시에도 보존하고 L0와의 중복 제거를 하지 않는다.
  Builder가 도메인, IP, 단축 목록을 다시 분석하지 않는다.
- H05는 서버 선언과 본문 앞부분의 추정 유형을 구분한다. 같으면 값 한 번, 다르면
  두 값과 불일치/설정상 동등 관계를 표시한다. 한 값만 있으면 기록된 값과 비교 한계를
  표시한다. H06은 관측한 확장자/본문 앞부분 유형의 목록 일치만, H07은 attachment
  응답 헤더의 다운로드 지시만 전달한다. 악성 파일이나 브라우저 실행으로 표현하지 않는다.
- H08의 생산 조건 설명은 `HTTP response contains a Refresh header`로 바로잡았다.
  최종 결과는 헤더 관측과 Refresh 이동 미수행을 명시한다. 시간과 주소가 모두 해석되면
  둘을 표시하고, 부분 해석/해석 실패이면 기존 합의대로 원문 헤더만 표시한다. 부분
  파싱값은 record/audit에 보존한다. 과거 원문이 없으면 있는 파싱값과 원문 미기록 한계를
  남긴다. 상대주소는 생산 단계에서 응답의 current_url을 기준으로 해석하며, Builder가
  URL을 새로 합성하거나 과거 저장된 결과를 소급 수정하지 않는다.
- H09의 HTTPS→HTTP 이동 지시는 새 HTTP 경로에 한 번 붙인다. 목적지 응답이 없어도
  지시가 관측됐으면 남기고, 음성/미확정은 별도 행을 만들지 않는다.
- HTTP 응답 미확보나 결과 부재를 표현하던 검사별 빈 포장과 자동 생성된 사유 미기록
  안내는 각 발생을 audit에 보존하고 모델에서 생략한다. 실제 수집 오류와 분석 예외는
  서로 다른 발생마다 이유와 대상을 남긴다. 원인 없이 응답 부재만 기록된 경우에는 그
  사실만 공통 한계로 표시한다. 기록 자체가 없으면 응답 수신 여부 미기록이라고 한다.
  L2 내부 실행 집계/저장 메타데이터는 audit에 두며, 본문 잘림/완전성 및 L2–L3의 같은
  응답 관측 연결은 모델에도 유지한다.
- C01의 음수 값에는 시간차를 24시간 단위로 내림한 정수라는 설명을 붙인다. C01/C02가
  같이 있을 때 C01 계산시각과 C02 검사시각이 같다는 추정을 막는 안내를 한 번 둔다.
  C02 상태 표현과 생산 결과는 그대로이며 시각을 추정하거나 재계산하지 않는다.
- C03의 표시명은 `TLS 접속 호스트와 인증서 이름 대조`다. typed_SAN이면 DNS/IP 유형을
  나누어 비교한다는 설명, CN 보완이면 SAN 부재에 따른 보완 비교라는 설명을 붙인다.
  과거 방식 미기록 결과에 현재 방식의 설명을 임의로 붙이지 않는다.
- `l2_certificate_context.C04Selection`은 서버 인증서 자체 서명 true/false를 같은 TLS
  정보에 자연어로 설명한다. true는 자신의 공개키로 자신의 서명이 검증됐다는 뜻,
  false는 자체 서명이 아니라는 뜻이며 발급자 신뢰는 별도 검사 대상이다. raw와 기록된
  bool이 다르거나 성공 결과와 같은 검사의 분석 실패가 충돌하면 구성 오류로 처리한다.
  인증서 부재는 공통 TLS 한계 한 번, 인증서가 있고 self_signed=null이면 검증 결과를
  얻지 못했으며 세부 원인이 미기록이라는 설명, 분석 예외는 실제 이유를 남긴다.
  raw 자체의 부재를 인증서 부재로 추정하지 않는다. subject/issuer 및 내부 포장은
  record/audit에 보존하고 C04 결과 행에 반복하지 않는다. C05–C08의 새 선별은 범위 밖이다.

모든 변경은 동일 입력의 raw/native → 저장 record 재조회 → Builder → 최종 Messages로
대조한다. 새 모델 및 Gateway 검사는 기존 검사 포장, 빈 값, 과장된 실행/신뢰 설명과
모호한 옛 표시의 재유입을 거부한다. 보존·선별·전송 검증과 실제 모델 이해도·배포 검증은
구별한다.

## L0 모델 전달 선택 — 2026-09-28

최신 사용자 지시에 따라 Builder 보완은 L0 / L1 / L23을 각각 진행한다. 이번 변경은 L0 전용 `l0_context.py`의 선택·안내와 공통 Builder의 연결, 최종 문서의 L0 부분 검증에 한정한다. 다른 계층의 선택 규칙과 공통 전송 포장·어댑터·Result 계약은 이번 L0 작업에서 바꾸지 않는다.

원본 URL은 requested_urls에 한 번 보관한다. url_subject는 그 위치(requested_url_index)와 raw의 호스트·등록 도메인·서브도메인 중 실제 있는 값만 제공한다. Builder는 새 URL 분석을 수행하지 않는다.

url_observation은 검사·관찰 배열·판단에 쓸 점으로 구성한다. 같은 검사와 동일한 안내를 묶지만 각 관찰의 위치·값·순번은 모두 남기며, 동일값의 반복 발생도 지우지 않는다. 접속 호스트와 등록 도메인이 공통 기본 정보와 정확히 같을 때만 그 반복 필드를 생략한다. 관찰 그룹의 각 원본 signal 위치는 audit의 source_pointers로 연결한다.

| record/audit 보존 | 모델 전달 |
|---|---|
| raw 원본 전체, 파싱 상태와 오류 | 원본 URL 참조와 실제 파싱된 기본 정보 |
| signals 전체 및 내부 목록 버전 | 관찰 내용·위치·발생별 값, 동일 판단 안내 한 번 |
| 실행·수집·분석 상태, errors, 집계, 해시, 저장 경로, 버전 | L0 모델 본문에 포함하지 않음 |
| DGA·타이포스쿼팅 안내 metadata | 항상 한 번 포함 |

단축 서비스·무료 발급 도메인·이중 확장자는 해당 종류의 record가 0건일 때만 고정된 추가 검토 안내를 넣는다. record 부재를 목록 불일치·검사 음성·안전 근거로 서술하지 않는다. TLD 통계 추측 안내는 추가하지 않는다. 추가 안내는 reading_guide.l0에 두고 사실을 인용하는 evidence로 취급하지 않는다. 이 guide는 Judgment v2 최종 입력의 layer_boundaries.reading_guide에도 보존한다.

context_source는 새 L0 raw/record를 전용 l0_url_observations에 무손실 보존한다. model_context와 최종 요청에서의 선별 규칙은 l0_context가 담당하며, validator가 메타 재유입·빈 관찰·중복 공통 정보·잘못된 조건부 안내를 거부한다. 기존 Judgment v2 공통 전송 무결성 정보(source_accounting)는 이 L0 내부 메타데이터 선택과 별개이며 기존 소비자 계약을 유지한다.

동일 입력의 native/raw/record → 저장 재조회 → Builder → Judgment v2 문서 → 실제 Messages 본문을 모형 전송으로 대조한다. 이는 선별·보존·요청 연결 검증이며 실제 모델 판단 품질이나 AWS 운영 적용의 증거가 아니다.

## 계층별 Builder와 L1 최종 선택 — 2026-09-28

사용자는 L0, L1, L23을 각각 검토·승인한 다음 최종적으로 합치는 순서를 정했다. L0의 선별은 `l0_context.py`, L1의 선별은 `l1_context.py`가 담당한다. 공통 `model_context.py`는 각 모듈의 선택 결과를 등록하고 전체 문서의 E ID를 배정한다. L23의 새 전용 선택 규칙과 최종 통합 문서 설계는 다음 검토 범위이며, 기존 L23 동작을 승인된 새 설계로 간주하지 않는다.

L1 독립 공개 함수는 `build_l1_context(record, raw, audit=...)`이다. 결과는 `{layer: "L1", subject: {lookup_host, registered_domain}, evidence: [{id, kind, ...facts}]}`이다. subject에는 원본에 실제로 기록된 조회 대상만 남긴다. 새 L1 생산 결과에는 입력 `target.original_url`과 파싱된 `target.lookup_host`를 보존한다. 과거 원본 URL이 없는 저장 record를 수정하거나 Builder가 URL을 재구성하지 않는다.

정상 주소 결과는 `dns_a_ip_asn`의 `address_selection`과 `networks`로 연결한다. 첫 두 고유 IPv4의 ASN·prefix·org가 모두 관측되어 같으면 `ipv4` 배열 하나로 묶으며, 실패한 IP는 별도 `ip_asn: not_observed`로 둔다. CNAME은 실제 이름 연결을 보존한다. IP 자체를 입력한 경우의 직접 ASN 결과도 `ip_asn` 항목으로 유지한다. NS 관계는 `dns_rdap_ns_comparison`이며 아래 NS 선택 규칙을 따른다. RDAP는 세 날짜, 도메인 상태, 등록대행사를 유지하고 임의의 위험도·경과일을 만들지 않는다. 조회 실패는 간단한 상태·이유로 표현하며 HTTP 429, SERVFAIL 등 실제 받은 응답은 보존한다.

독립 L1 문서에는 question, 문서 버전, 원본 URL 목록, 일반 HTML/JS 안내, coverage·실행·저장 메타데이터가 없다. 기존 Gateway와 연결하는 공통 문서에서는 같은 선택 사실을 `{id, kind, facts}`로 감싸고 `layer_subjects.l1`에 대상을 한 번 둔다. 이는 호환 연결이며 별도 선별이나 record 재유입 경로가 아니다. Judgment v2도 이 대상을 `layer_boundaries.layer_subjects`로 유지한다. L0/L1만 있는 공통 문서에는 L0 전용 안내 외에 페이지·스크립트 일반 안내를 붙이지 않는다.

record와 raw는 보존하며, audit의 source context에는 L1 원본 raw와 정규화된 모든 signal·원인·실행 정보가 남는다. 최종 문서 validator는 L1 record 포장, 불필요한 필드, 중복 네트워크/NS 목록, L0/L1 문서의 HTML/JS 안내 재유입을 거부한다. 이전 저장 모델 문서는 이전 형식으로 읽을 수 있다.

같은 입력의 native/raw → 저장 record 재조회 → 독립 L1 문서 → L0+L1 공통 문서 → 실제 Gateway 직렬화 요청을 로컬 모의 전송으로 확인했다. 이는 선택·저장·전송 계약 검증이며 실제 모델 품질·AWS 배포·L23 설계 완료가 아니다.

## Builder 선별 게이트 — L1 NS (2026-09-23, 선택 원칙 유지)

Builder의 목표는 record를 짧게 복사하는 것이 아니라 **URL 판정에 도움이 되는 차이와 관측 한계만 최종 모델 문서에 선택**하는 것이다. raw와 record는 조회별 원본·결과를 유지하고, 생략한 자료는 감사 문서에서 추적한다. 조회 결과와 그 결과로 만든 비교를 나란히 반복해서 모델에 보내지 않는다.

L1 NS에서는 등록 단위 DNS NS와 RDAP nameservers가 일치하면 모델 문서에 등록 단위와 `matched` 관계만 둔다. 다르면 `different`와 DNS에만 있는 이름·RDAP에만 있는 이름만 둔다. 비교가 성립하지 않으면 일치·불일치를 만들지 않는다. URL 호스트의 NS는 등록 단위 대조와 별개이며, 하위 호스트에서 실제 값이나 조회 문제가 있을 때만 독립 관측으로 고려한다. 등록 단위 NS 목록과 대조에 쓰인 RDAP nameservers 목록은 record에 남고, 비교 관계와 함께 모델 문서에 중복 게시하지 않는다.

2026-09-29 누락 보완: 등록 단위 NS의 `응답 수신`은 이름 목록 확보와 다르다. 목록 결과(`records`)만 기존 비교용 생략을 적용하며, SERVFAIL·REFUSED·NXDOMAIN 등 실제 받은 응답 코드는 `dns_ns_registration.response` 또는 `response_codes`로 최종 모델 문서까지 유지한다. 호스트와 등록 단위가 같아 DNS NS를 재사용한 경우에도 같다. 이 응답만으로 NS 일치·불일치나 URL 활동 판정을 만들지 않는다. raw·record는 변경하지 않으며 기존 성공·빈 목록 생략과 ID·응답 검증 계약을 유지한다.

`l1_context.validate_l1_selection`은 `model_context.validate_model_context`와 Judgment v2에서 호출된다. 등록 단위 NS record 포장 유출, 비교와 RDAP nameservers의 중복, 일치 관계에 목록이 붙은 출력을 거부한다. `tests/test_l1_ns_dual_scope.py`는 동일 native 입력의 raw → record → 최종 Builder 문서와 이 거부 조건을 검사한다. 향후 Builder 필드를 늘릴 때에는 “모델 판정에 어떤 새 구별을 주는가”를 먼저 정하고, 단순 조회 전문 복제라면 record·audit에만 남긴다.

## 서로 독립인 공통 상태

| 축 | 상태 | 의미 |
|---|---|---|
| execution | completed / failed / not_performed / interrupted / unrecorded | 생산 실행의 완료 여부. 반환 객체 존재만으로 completed로 하지 않음 |
| acquisition | observed / partial / unavailable / not_attempted / unrecorded | 해당 입력·응답 확보 범위. 기술 분석 예외는 수집 실패가 아님 |
| analysis | completed / partial / unavailable / not_performed / unrecorded | 제공된 기술 결과와 분석 한계. 전체 URL 결론과 별개 |
| 각 근거 assessment | predicate / applicability / certainty / url_verdict / limits | 좁은 기술 조건, 적용 여부, 해석의 경계를 분리. 확률·confidence를 새로 만들지 않음 |

`execution.completed`는 생산자가 자신의 실행을 끝냈다고 기록했음을 뜻한다. 수집 실패가 있어도 실행은 끝날 수 있다. 세부 단계 기록이 없는 과거 결과는 `individual_execution_parts_not_recorded`이며, 세부 단계를 꾸며내지 않는다. legacy `analysis_status`는 이전 소비자를 위한 축약 필드이고 새 모델 문서에서는 독립 축이 있는 경우 제외한다.

| 계층 | native 입력과 공통 축의 매핑 | 대조 사례 |
|---|---|---|
| L0 | `analysis_execution`과 `raw_evidence.parse_status`; 입력 문자열 확보와 분석 수행을 분리 | 빈/무효 입력: 실행 종료, 입력 확보, 분석 미수행; 가짜 음성 18개를 만들지 않음 |
| L1 | `전체상태`/`실패사유`, `observation`, `detail.failure_occurrences` 또는 과거 `detail.dropped`, `query_lifecycle` | IP-ASN 일부 성공: acquisition.partial, analysis.completed 가능. 미완료 Future는 Timeout으로 바꾸지 않음 |
| L2 | `scan.status`, 실제 HTTP 응답·TLS 인증서, body_complete, acquisition-impact occurrences | 수집 성공 + 한 분석기 예외: execution.completed / acquisition.observed / analysis.partial |
| L3 | `scan.status`, HTML source None 대 빈 문자열, JS source/semantic coverage, 단계별 오류 | None은 미확보; 빈 문자열은 확보한 빈 입력. 외부 스크립트 두 실패는 별도 발생 |

공통 validator는 모든 현재 record에 적용한다. 알려지지 않은 native 단계/대상은 `None`/`unrecorded`이며 Builder가 이름이나 오류 문구에서 추론하지 않는다. 서로 다른 record 위치는 별도 발생이고, 생산자가 명시적으로 공유한 occurrence만 동일 대상으로 연결한다. 같은 오류 문구가 같은 근본 원인이라는 주장은 하지 않는다.

## L0 공개 생산 모델의 변경

각 evaluation은 `facts`에 0개 이상의 비교·측정·관계를 담는다. 단일 위험 플래그나 첫 후보를 골라 내보내지 않는다. `predicate.result`는 기술 조건의 `matched`, `not_matched`, `not_evaluated`, `unresolved`이고 URL verdict가 아니다. normalized record는 새 evaluations를 직접 소비하여 `detected` bool로 축소하지 않는다.

| 검사 | 생산하는 근거와 범위 |
|---|---|
| Combo | 모든 브랜드 × domain/subdomain 라벨 × 위치. exact label, 부분 문자열, 참조 도메인 일치가 구분됨. 목록 일치로 소유권을 확정하거나 관계를 삭제하지 않음 |
| Typo | 모든 시각 골격 포함 관계와 임계 내 편집거리 후보; 동률도 보존. 짧은 브랜드 제외, 원문 포함 관계 제외, 편집거리 미수행, 임계 초과 거리의 미계산 범위를 기록 |
| IDN | 모든 IDN 라벨의 디코딩·스크립트 집합·브랜드 골격 관계. 실패한 라벨은 별도 analysis limitation |
| TLD | 관측 suffix·길이·대조 목록 버전·정확한 목록 일치. 목록 불일치는 안전 결론이 아님 |
| 파일·이중 확장자 | 경로 마지막 성분과 각 쿼리 값의 비교, 위치·parameter/value_index, 미등록 확장자·기술 역할. 실제 파일 수신·실행 미관측 |
| XSS 문자열 | 모든 설정 패턴의 각 성분 내 매칭 위치·디코드 깊이; 서로 겹치는 매칭을 독립 공격 수로 계산하지 않음. 디코드 한계가 음성을 확정하지 않게 함 |
| 쿼리 목적지 | 각 후보의 원문·위치·해석 결과. same-domain, 외부 도메인, IP, 파싱 실패·도메인 미확정을 구분; 실제 리다이렉트는 관측하지 않음 |
| DGA·길이·Base64·userinfo·subdomain·scheme | 측정값/임계·개별 payload와 위치·실제 URL 구조를 보존. 생성 방식·의도·사칭 확정은 하지 않음 |

구형 L0의 `해당없음`은 검사 음성과 비대상을 구분하지 않았으므로 현재 adapter가 새로운 음성으로 확정하지 않는다. `legacy_status`와 원래 value를 보존하고 적용 여부를 미기록으로 둔다. 과거에 버린 후보를 Builder가 복원하지 않는다.

## 모델 문서와 감사 문서

모델 문서는 관측 범위 → 페이지/폼/필드 → 스크립트와 이벤트 → 기술 평가 → 별도 한계 순서로 조직한다. 각 근거는 짧은 `E` ID를 갖고 관계는 `evidence_ref`로 연결한다. 같은 계층 평가의 동일한 해석 계약은 coverage의 `shared_check_contract`에 한 번 두며 해당 평가가 명시적으로 참조한다.

보존된 코드·원문·기술 연결은 그대로 유지한다. 전체 객체가 정확히 같거나 명시적 참조 대상의 필드와 같은 값일 때만 중복을 제거한다. 누락 관계는 `not_supplied`/`ambiguous`로 표시한다. 관측된 빈 문자열, 미기록 값, HTML 속성 부재, 제공된 빈 배열은 서로 구분한다. 페이지가 선언한 metadata는 데이터로 보존한다.

저장 키, request/snapshot ID, 해시, 원문 위치는 외부 `context-audit.json`에 둔다. 감사 문서는 원본 source context와 `E ID → source pointer / original ID`를 보유한다. 인용 스키마와 응답 validator는 최종 문서의 같은 E-ID 집합을 쓴다.

100 KB를 넘는 문서는 복원 가능한 inventory 표현을 먼저 적용한다. 이후 Gateway는 설정된 토큰 예산에 따라 다시 표현을 선택하고, 적합하지 않으면 구성/서비스 실패로 기록한다. 증거를 조용히 잘라 보내거나 URL verdict로 바꾸지 않는다.

## 검증 근거와 남은 제한

`tests/test_model_context.py`, `tests/test_url_evaluations.py`가 현재 생산→record→모델→Gateway 모형 전송을 검사한다. 기존 관계 보존 검사는 내부 source/relationship view의 보존 대상으로 남기고 새 공개 문서 검사를 별도로 둔다.

외부 실행 자료는 `evaluation/remediation-20260911/results/context-purpose-*`에 보존한다. `interaction-20260911/context-purpose-evidence.py`는 같은 합성 입력으로 기준선과 후보의 실제 전송 본문을 만든다. 저장 자료 3개는 원문 재수집 없이 표시 방식만 비교한다. 저장 자료에서 과거 누락된 원문·생산 상태·후보를 복원했다는 주장은 하지 않는다.

첫 후보에서 반복된 해석 설명이 늘어난 것을 실제 본문 비교로 확인해 공통 계약 공유로 줄였다. 새 후보의 합성 입력 전체 크기는 새로 보존한 근거·범위 때문에 구형보다 크다. 따라서 전체 토큰 감소나 판단 품질 향상은 검증된 결론이 아니다. 작은 저장 입력은 문서 구조 비용으로 커질 수 있고 큰 입력은 inventory 압축의 영향을 받는다. 비교 자료의 가짜 token count는 예산 분기 확인 전용이다.

L1 native `verify_*`는 네트워크 조회와 출력 폴더 정리를 수행하므로 실행하지 않는다. 실제 query 함수와 출력 계약은 네트워크를 막은 통제 입력으로 검사한다. 기존 AWS baseline·원본·모델 판단 품질은 이번 로컬 코드 검토와 구분한다. 독립 검토자의 고정 커밋 반례 확인 전에는 완료로 표시하지 않는다.

## 독립 검토 후 R1·R2 후속 수정

bd99bb0에서 독립 검토자가 기존 452 검사, L0 반례 17개, L2 수집/분석 독립 축, 실제 모형 전송 5개 및 저장 입력 대조를 확인했으나 두 문제를 재현해 완료를 승인하지 않았다.

- R1: 필드 분류 예외가 JS 준비에서는 L3 전체를 중단하고 HTML 분석에서는 앞서 성공한 필드를 버렸다. 현재는 스캐너가 필드별 실패를 격리하여 한 번 생산한 `credential_classification`을 HTML·JS가 공유한다. 성공 필드·실패 필드·후속 필드와 각 실제 발생을 보존한다. 알려진 양성 관계는 유지하고 해당 범위의 음성은 미확정으로 둔다.
- R2: 새 공통 record에 필수 assessment가 빠지거나 상태/원인 연결이 모순되어도 통과했다. 현재 validator는 선언된 버전, 필수 구조·타입·enum, 상태/적용/기술 결과의 일관성, 실행 결과 개수, 양방향 원인 연결과 acquisition 원인 참조를 검사한다. 신형 손상을 과거 미기록으로 덮지 않는다.

`tests/test_context_round2.py`는 앞뒤 성공·중간 실패, 모든 필드 실패, 복수 실패, JS 유무, 서로 다른 실패 대상, 공유 발생과 일부 양성 보존을 검증한다. 손상 record는 validator와 Builder 양쪽에서 거부하고 유효한 legacy 미기록은 수용하는 대조를 포함한다.
