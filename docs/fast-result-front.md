# Front 연동 가이드 — 확정된 빠른 분석 결과

기준: [확정된 Notion 설계](https://app.notion.com/p/2ae3dea100f783c596d901663edab660). 공개 계약은 `fast-result-1`, 검사는 `evidence_pipeline/fast_public.py`, 공통 화면 동작은 `frontend/fast-result-renderer.js`다.

## 1. 책임

| 담당 | 만드는 것 |
|---|---|
| Builder 코드 | 항목 종류·선별된 값·관계·조건에 맞는 쉬운 설명과 기존 기술 정보 |
| 기존 Sonnet 5.5 판정 호출 | 판정·짧은 요약·이유와 관련 항목 선택 |
| 서버 | 선택한 관련 항목을 이번 Builder의 사실 ID로 연결한 공개 응답 |
| 공통 렌더러 | 상태·판정 표시명, 이유 펼침, 실제 사실·조건 연결, 카드 중복 제거, 기술 정보 펼침·이동 |
| 서비스 연동 담당 | 인증·접수·조회·요청/시도 일치 확인·결과 교체·심층 요청 연결 |
| Front 디자인 | 공통 결과 영역의 배치·색상·글꼴·여백·반응형 레이아웃 |

Front 디자인 작업은 공통 코드가 만든 문구와 연결을 그대로 사용한다. URL별 문구 사전이나 자유로운 위험 해석을 만들지 않는다.

## 2. 제공된 화면 사용

`frontend/fast-result-renderer.js`를 불러온 뒤 결과 조회 코드가 받은 JSON을 그대로 전달한다.

```js
FastResult.render(document.querySelector('#analysis'), apiResult, {
  url: submittedUrl
});
```

기본 화면은 판정, 짧은 요약, 중요한 이유 최대 3개다. 나머지 이유와 확인된 내용은 버튼으로 펼친다. 이유의 근거 버튼은 서버의 실제 `related_fact_ids`와 해당 사실의 `condition_fact_ids`를 열며 같은 카드를 중복 작성하지 않는다. 연결된 실제 사실이 없으면 이동 버튼을 만들지 않는다.

서버의 항목 연결은 이번 결과에 존재하는 이름에만 적용한다. 표기 차이·제한된 한글 오타가 보정돼도 모델이 잘못 선택한 사실의 의미를 코드가 재판정하지 않는다. Front는 서버의 연결을 그대로 사용하며 판정·이유·상세를 다시 작성하지 않는다.

상세 기본 내용은 `plain.title / plain.text`이고 기술 정보 펼침에는 기존 `text`를 사용한다. 이전 결과에 `plain`이 없어도 원래 제목과 기술 정보 펼침으로 읽는다. 문자열은 `textContent`로 표시한다.

디자인용 선택자는 [frontend/README.md](../frontend/README.md)에 있다. 문구·판정·근거 연결과 버튼 접근성 이름·의미는 유지한다.

## 3. 공개 응답

| 필드 | 사용 |
|---|---|
| `schema_version` | `fast-result-1` 계약 식별 |
| `judgment_status` | accepted에서만 판정 표시. pending·not_requested·failed·invalid는 처리 상태 |
| `judgment.verdict / summary / reasons` | 모델의 판정·요약·중요도 순서의 이유 |
| `reasons[].related_fact_ids` | 서버가 연결한 상세 사실 |
| `details.facts[]` | Builder의 공개 사실. 각 사실의 ID·plain·text·조건 연결 |
| `details.sections[]` | 해당 결과의 공개 구획과 사실 배치 |
| `job_id / attempt` | 현재 요청·시도의 결과인지 확인 |
| `context_revision / result_revision` | 판정·상세·캐시·심층 요청의 같은 결과 식별 |
| `deep_analysis.available` | 현재 결과의 심층 입력 준비 가능 표시. 버튼은 서비스 API를 통해 현재 결과를 L4에 연결 |

처리 실패와 모델의 UNKNOWN 판정을 구별한다. UNKNOWN의 빈 reasons는 허용된 정상 형식이다. 관련 이름을 Front에서 다시 비교하거나 비슷한 사실 ID로 교정하지 않는다. 원본·Record·S3 매핑·자료 범위·미확인·한계 목록은 공개 결과에 추가하지 않는다.

### 다섯 판정과 이전 결과

| 새 `judgment.verdict` | 공통 렌더러 표시 |
|---|---|
| `BENIGN` | 정상 |
| `LIKELY_BENIGN` | 정상 가능성 높음 |
| `LIKELY_MALICIOUS` | 악성 가능성 높음 |
| `MALICIOUS` | 악성 |
| `UNKNOWN` | 판단불가 |

새 모델 응답은 이 다섯 값만 수용한다. 기존에 저장된 `SUSPICIOUS`는 읽기 호환을 위해 ‘의심’으로 표시하며 새 판정으로 변환하지 않는다. 디자인 담당자는 공통 렌더러를 사용하면 되고 별도 분류 로직을 만들지 않는다.

가능성 등급의 방향 근거와 중요한 미확정은 내부 `decision_notes.provisional_assessment`, 판단불가의 핵심 공백은 내부 `decision_notes.unknown`에 저장한다. 두 객체는 공개 응답과 Front에 전달하지 않는다. 정상·악성에서는 두 객체가 `null`이다. `failed`·`invalid`는 처리 상태이므로 판단불가 배지로 표시하지 않는다.

판정 기준과 공개 문구는 [실제 모델 지시](../evidence_pipeline/fast_judgment_prompt.txt)에 있다. 기본 이유는 핵심 관계 1–2개이며 필요한 별도 관계가 있을 때만 세 번째를 쓴다. 모델이 작성한 판정·요약·이유를 서버나 Front가 규칙으로 다시 쓰지 않는다. 계약 구현, 실제 모델 지시 준수, 운영 버전 적용은 각각 검증한다.

## 4. 서비스 공통 연동

실제 서비스 Front 초안은 [CloudFront 화면](https://d2gmygchoew9ed.cloudfront.net/)이다. 새 `/api/*` 경로는 Cognito access JWT와 `team5-web/analysis` scope를 확인하고 사용자 소유 분석만 제공한다. 구현은 [Front 사용법](../frontend/README.md), `frontend/auth.js`, `frontend/service-client.js`, `web_service/api.py`에 있다.

- POST `/api/analyses`: `{url, request_id, virustotal, model_choice?, reasoning_effort?}`의 202 접수 후 Fast SSE를 바로 연다. 서버 내부에서 Gate를 호출한다.
- GET `/api/analyses/{scanId}/events`: access token을 Authorization header로 전달하는 SSE. Fast 결과는 기존 Result4의 `fast-result-1` 그대로이며 서버가 변경된 snapshot을 보낸다.
- 선택 VT는 별도 POST와 `/virustotal/events` SSE를 사용한다. 접수·조회 지연·한도·오류가 Fast 접수·결과 표시를 기다리게 하지 않는다.
- SSE가 끊기면 현재 사용자/요청으로 재연결하고 화면 이탈 시 취소한다. 상세 클릭은 받은 내용의 펼치기다. 접수 응답 유실만으로 새 POST를 자동 반복하지 않는다.
- 새 요청·재분석의 응답이 이전 화면을 덮지 않도록 요청 세대·job·attempt를 확인한다. 같은 ID 재분석에서는 이전 완료 attempt보다 큰 결과를 기다린다.
- result revision이 바뀌면 같은 결과의 판정과 상세를 한 번에 교체한다. 사실 ID는 현재 context 안에서만 사용한다.
- 인증·HTTP 오류는 분석 판정으로 바꾸지 않는다.

이전 dev API `https://2j5rwcog6j.execute-api.ap-northeast-2.amazonaws.com/dev`와 CUSTOM 인증은 보존한다. 그 서버용 공통 토큰을 새 Front에 배포하지 않는다. 기존 Fast Lambda·SFN·Builder·모델 지시를 새 인증 코드로 바꾸지 않는다.

심층 버튼은 현재 `job_id`, `attempt`, `context_revision`, `result_revision`을 POST `/api/analyses/{scanId}/deep`에 전달한다. 서버가 소유권·현재 입력을 확인하고 L4 start가 실행을 생성/재사용한다. Front는 `/api/deep/{run_id}/events`로 공개 진행·상세·최종 결과를 받는다. 내부 Builder·전체 Judgment·매핑은 L4 서버가 읽으며 최초 캡처는 L4가 직접 페이지를 열어 만든다. 사용자 클라이언트에 Fast 원본이나 S3 매핑을 내려주지 않는다. L4의 추가 캡처·페이지 통신 기록은 접힌 자료 영역에서 연다.

## 5. 현재 적용 상태 — 2026-10-06

AWS의 EC2 수집·Activity·Builder, Sonnet 5.5 판정과 Result4를 실제 Front에서 호출한다. 쉬운 설명은 코드가 생성하며 추가 모델 호출은 없다. Front 연결 작업에서 기존 Builder와 Fast 판정 경로를 변경하지 않았다.

후속 공통 보완은 Context 20·Judgment 26·L23 19에 적용했다. JavaScript의 순수 콘텐츠 데이터에서 빠진 문구·주소 관계를 기존 분석에 추가하고, 근거 항목의 표기 연결과 합의된 판정 기준의 적용 지시를 보완했다. 공개 응답 형식·Cognito·소유권 확인·Gate2·Result4·Fast/VT/Deep 연동은 유지했다. [공통 처리와 검증 범위](fast-result-plain-explanations.md)를 따른다.

실제 Cognito 로그인 후 새 `https://www.rust-lang.org/` 요청에서 Sonnet 5.5 판정·61개 쉬운 상세 사실·12개 근거 연결과 독립 VT 결과를 받았다. 현재 Fast 결과의 네 식별자로 L4를 시작해 실제 최종보고를 수신했다. 초기 캡처와 L4 모델·Store 검증은 L4 구현의 별도 증거와 대조한다.

- [서비스 배포·동작 확인과 시간 경계](web-service-deployment.md)
- [Front 디자인과 공통 연동 사용법](../frontend/README.md)
- [공통 쉬운 설명 생성 계약](fast-result-plain-explanations.md)

이 확인은 실제 한 요청의 연결과 결과 보존 증거다. 모든 URL의 판정 품질·속도나 L4의 모든 도구 실행을 검증했다는 의미로 사용하지 않는다. 이전 모델 비교·성능 실험과 원본 증거는 저장소 밖의 작업 폴더에 보존한다.

## 6. 모델·추론 강도 선택 계약 — 2026-10-08 구현

인증된 GET `/api/analysis-models`는 `{default_model_choice, models:[{id,label,efforts,default_effort}]}`를 반환한다. Front는 서버 목록만 사용한다. `efforts`는 해당 모델에 허용한 문자열 목록이며 `default_effort`는 그 목록의 기본값이다. 강도 선택을 지원하지 않는 설정은 빈 목록과 `null` 기본값으로 표시하며 POST에서 `reasoning_effort`를 생략한다.

`reasoning_effort`는 선택 사항이지만 보내는 경우 `model_choice`와 함께 정확한 문자열로 보낸다. 명시적 `null`, 빈 문자열, 숫자, 해당 모델에 허용하지 않은 값은 저장·실행 전에 거부한다. 강도를 생략하면 그 모델의 서버 기본값을 적용한다. 202 응답의 `model_choice`, `reasoning_effort`로 실효 선택값을 확인한다. 모델·강도 없이 보내는 기존 요청은 기존 환경 설정 경로를 유지한다.

`request_id`의 동일 입력은 모델 ID와 실효 강도를 포함한다. 생략과 명시적 기본값은 같은 요청이다. 같은 ID로 강도를 바꾸면 409가 된다. 이전에 접수된 요청에 강도 필드가 없으면 보존한 profile에서 복원하며, 이전 접수 응답에도 그 값을 제공한다. 운영 기본값이 바뀐 뒤 생략한 재요청은 새 기본값으로 비교하므로 409가 될 수 있다. 이 경우 이전 실효 강도를 명시해야 기존 접수를 조회할 수 있다.

서버 설정 `FAST_MODEL_CHOICES_JSON`의 각 모델에 추가하는 `efforts`는 허용 능력 정보다. `output_effort`는 기본값이다. 기존 설정에 `efforts`가 없으면 기존 `output_effort` 하나만 허용하며, 그 값도 없으면 강도 선택을 제공하지 않는다. API와 Gate가 선택값을 확인한 뒤 기존 7필드 profile의 `output_effort`에 실효값을 고정한다. 허용 목록은 profile/hash에 넣지 않는다. SFN은 고정 profile을 Judgment로 전달하고 실제 Bedrock 요청의 `output_config.effort`에 사용한다. 한 attempt에서 다른 profile로 재시도할 수 없다. 별도의 thinking token budget으로 변환하지 않는다.

운영 목록과 모델 호출 권한은 적용 담당자가 확인해야 한다. 5단계 강도 지원은 완료시간이나 판정 품질을 보증하지 않으며 현재 provider timeout/max_tokens 상한은 유지한다. 이 문단은 구현 계약이며 실제 계정의 활성 모델·배포·제공자 수락 증거는 별도 배포 기록을 따른다.
