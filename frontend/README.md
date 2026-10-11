# 실제 서비스 Front 초안

`index.html`은 로그인, URL 입력, 빠른분석, 선택 VirusTotal 결과, 심층분석, 내 분석 기록을 담는 서비스 화면이다. `config.json`은 배포 스크립트가 실제 공개 Cognito 설정으로 생성한다. API key·공통 토큰·AWS 자격증명을 넣지 않는다.

## 디자인 담당자가 바꿀 곳

| 파일 | 책임 |
|---|---|
| `theme.css` | 색상·글꼴·간격·반응형 배치. `:root` 값부터 변경한다. |
| `index.html` | 서비스 화면의 배치·소개 문구. 기존 요소의 `id`·label·버튼 역할을 유지한다. |
| `fast-result-renderer.js` | 서버가 제공한 판정, 이유와 연결된 확인 사실을 표시한다. 관련 근거·기술 상세를 펼치는 동작은 이미 구현돼 있다. |
| `virustotal-renderer.js` | 외부 제공자의 통계·기록 시각·엔진별 결과를 별도 영역으로 표시한다. |
| `deep-result-renderer.js` | L4 업무 이름·현재 상황을 기본 화면에 표시한다. 업무를 펼치면 시간순 진행 내역을 먼저 보여주고, 질문·답변·작업·자료는 추가로 펼친다. 최종보고는 주요 확인 내용 3개부터 보여준다. |
| `app.js` / `service-client.js` / `auth.js` | 인증, API 요청, 현재 요청 유지, SSE 수신, 오류·로그인 복구. 디자인 변경을 위해 다시 구현할 부분이 아니다. |

서버의 `fast-result-1` 내용을 Front에서 재판정하거나 전문 용어를 임의 규칙으로 재작성하지 않는다. 판정 이유의 `related_fact_ids`는 같은 응답의 `details.facts`로 이동하며 사실을 별도로 복제하지 않는다. 기본 화면은 간결하게, 나머지는 로컬 펼치기로 보여준다.

새 판정은 정상(`BENIGN`)·정상 가능성 높음(`LIKELY_BENIGN`)·악성 가능성 높음(`LIKELY_MALICIOUS`)·악성(`MALICIOUS`)·판단불가(`UNKNOWN`)다. 공통 렌더러가 표시명을 제공한다. 이전 `SUSPICIOUS` 기록은 ‘의심’으로 읽으며 다시 분류하지 않는다. 처리 실패는 판정과 별도 오류 상태다. 가능성 등급·판단불가의 내부 유보 기록은 Front 응답에 포함되지 않는다.

## 요청 흐름

1. Cognito 로그인: authorization code + S256 PKCE. Access/refresh token은 메모리에만 유지한다. 새로고침하면 다시 로그인한다.
2. `POST /api/analyses`: `{url, request_id, virustotal:false|true}`. 서버가 URL 접수를 수행하고 사용자 소유 `scanId`를 반환한다.
3. `GET /api/analyses/{scanId}/events`: Bearer access token을 붙인 Fast SSE 연결. 선택한 VT는 별도 `POST /api/analyses/{scanId}/virustotal` 뒤 `/virustotal/events` SSE로 연결한다. VT 접수와 결과를 기다리는 동안에도 Fast 연결·결과 표시는 계속된다.
4. 관련 근거·추가 이유·엔진 목록을 클릭하면 이미 받은 응답을 Front에서 펼친다. 클릭 때문에 분석을 다시 실행하지 않는다.
5. 심층분석 클릭: `POST /api/analyses/{scanId}/deep`에 **현재 응답**의 `job_id`, `attempt`, `context_revision`, `result_revision`만 보낸다. 서버는 소유권과 현재 입력을 확인한다.
6. `GET /api/deep/{run_id}/events`: 서버가 L4 DB의 공개 snapshot을 조회해 SSE `deep` 이벤트로 보낸다. 업무별 현재 상황과 시간순 진행을 표시하고, ‘해당 기록 보기’에서 업무 안의 작업·도구 실행·결과로 이동한다. 처음 요청한 입력과 실제 전달한 입력, 작업자의 보고와 도구 결과를 구별한다. SSE 갱신 후에도 펼친 상세를 유지한다.

새 요청·다른 기록 열기·로그아웃은 이전 연결을 중단한다. 이전 분석의 늦은 응답이 새 화면을 덮어쓰지 않는다. 토큰이나 API key를 query string에 넣지 않는다.

## API 계약

| 경로 | 결과 |
|---|---|
| `GET /api/analyses` | 로그인 사용자의 최근 분석 기록 |
| `POST /api/analyses` | 접수 결과. 같은 `request_id` 재전송은 같은 접수를 재사용 |
| `GET /api/analyses/{scanId}` | 기존 Result4가 반환한 `fast-result-1` 그대로 |
| `GET /api/analyses/{scanId}/events` | `fast`, `heartbeat`, `reconnect` SSE |
| `GET /api/analyses/{scanId}/virustotal/events` | 독립 `virustotal` SSE |
| `GET /api/analyses/{scanId}/virustotal` | 독립 `virustotal-url-report-1` |
| `POST /api/analyses/{scanId}/virustotal` | 이 분석에 대해 명시적으로 추가 조회 선택 |
| `POST /api/analyses/{scanId}/deep` | L4 `run_id`와 `events_url` |
| `GET /api/deep/{run_id}` | 사용자 소유 L4 공개 결과 |
| `GET /api/deep/{run_id}/events` | L4 공개 상태·진행·상세·최종 결과 SSE |

모든 API 경로에는 Cognito access JWT와 `team5-web/analysis` scope가 필요하다. 다른 사용자 소유 ID는 404, 로그인 만료는 401, 변경된 Fast 입력으로 심층분석을 시작하면 409다. Fast 원본·Record·S3 매핑·내부 모델 사고과정을 사용자 응답에 넣지 않는다. L4가 추가로 수집한 캡처·페이지 통신 기록은 L4 공개 계약에 따라 소유 사용자에게 접힌 자료 영역으로 제공한다.

## 디자인용 선택자

| 영역 | 유지할 요소와 선택자 |
|---|---|
| 로그인·접수 | `#login`, `#logout`, `#analysis-form`, `#target-url`, `#submit`, `#vt-option` |
| Fast 결과 | `#analysis`, `.result`, `.reasons`, `.evidence`, `.fact`, `.link`, `.more` |
| 별도 VT | `#virustotal`, `.provider-result`, `.provider-summary`, `.provider-engines` |
| 심층분석 | `#start-deep`, `#deep-panel`, `#deep-status`, `#deep-progress`, `#deep-result`, `.deep-record` |
| 업무·진행 | `.deep-work`, `.deep-work-summary`, `.deep-work-title`, `.deep-work-now`, `.deep-activity`, `.deep-activity-event`, `.deep-activity-time` |
| 기록·오류 | `#history-panel`, `#history-list`, `#service-error`, `#request-status` |

버튼의 이벤트 연결 대상 `id`, 입력의 label 연결, 상태·오류의 접근성 역할은 유지한다. 본문과 카드의 CSS 클래스는 공통 렌더러가 생성한다. 디자인 담당자는 응답 필드를 분석하거나 근거를 다시 선택할 필요가 없다.

## VirusTotal 선택

체크박스는 기본 해제다. 선택한 URL을 VirusTotal에 보내 기존 URL 보고서를 GET으로 조회한다. 자동 제출·재검사를 하지 않으며 자료 시각을 표시한다. 404는 ‘기존 결과 없음’, 한도·장애는 VT 영역의 상태로 표시한다. 우리 판정·Builder·L4 입력에 VT 결과를 넣지 않는다.

제공된 무료 key 기준의 서버 전체 한도는 16초 간격, 500회/UTC일, 15,500회/UTC월이다. 대기는 Step Functions로 수행하며 화면 조회·상세 클릭은 제공자 quota를 사용하지 않는다. 서비스 밖에서 같은 key를 사용한 양은 자체 장부에 없으므로 실제 429도 별도로 처리한다. 현재 key는 교육 실험용이다. [VirusTotal 공식 API 조건](https://docs.virustotal.com/reference/public-vs-premium-api)을 따라 상용 서비스에는 맞는 계약의 key를 사용한다.

## 배포와 확인

`deployment/deploy_web_service.py`는 승인된 새 역할·장부·secret·Cognito·REST API·CloudFront만 구성한다. Fast Gate2/Result4와 기존 수집·Builder·Sonnet 경로는 고정 버전을 호출한다. CloudFront는 private S3의 정적 Front 경로만 공개하고 `/api/*`는 인증된 API로 전달한다. `--phase rollback`은 새 Front/API를 가역적으로 비활성화한다.

현재 배포와 실제 검증 범위는 [서비스 배포 확인](../docs/web-service-deployment.md)에 있다. 이 초안에서 실제 로그인·API·모델·선택 VT·심층 실행을 연결했으며, 디자인 담당자는 HTML과 CSS부터 수정하면 된다.
