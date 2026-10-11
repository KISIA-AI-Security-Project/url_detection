# get_page_state의 text·links — 같은 페이지의 본문과 링크 읽기

현재 SDK 연결은 [AGENTS_SDK.md](AGENTS_SDK.md)를 따른다. 아래 날짜가 붙은 초기 검증은 당시 범위이며, 현재 검사 자료는 [정리 검증 기록](../output/l4-sdk-cleanup-20261002/)에서 확인한다.

현재는 [get_page_state](PAGE_QUERY.md)의 include로 본문·링크를 선택한다. 이전 get_page_content는 공개 Tool에서 제거했다. 기본 상태와 함께 읽으며, 요소도 필요하면 같은 호출에서 elements를 추가한다. 별도 브라우저를 열거나 URL을 다시 요청하지 않는다.

## 연결과 입력

```python
from l4_orchestrator.page_content import PageContentReader
from l4_orchestrator.tools.get_page_state import GetPageStateTool

content = PageContentReader(
    state,  # 기존 Tool과 공유하는 PageState
    timeout_ms=content_timeout_ms,
    max_text_bytes=text_limit_bytes,
    max_links=link_limit,
    max_links_bytes=links_limit_bytes,
)
tool = GetPageStateTool(state, elements=elements, content=content)
result = await tool.execute({
    "action_id": "read-login-page",
    "tool": "get_page_state",
    "target": None,
    "params": {"include": ["text", "links"]},
    "context": {
        "job_id": job_id, "scenario_id": scenario_id,
        "step_id": step_id, "state_id": None,
    },
})
```

`action_id`는 호출측이 정하는 식별자이며 위 문자열은 예시다. elements는 같은 state를 사용하는 기존 ElementRegistry다. 운영 한도 네 가지도 호출측이 제공한다. 시간·본문 바이트·링크 수는 1 이상의 정수, 링크 바이트는 빈 JSON 배열 `[]`을 표현할 수 있는 2 이상의 정수다. `params.include`에 text 또는 links, 둘 다 필요하면 두 항목을 넣는다. 이전 params.kind나 임의 JavaScript는 받지 않는다.

`state_id=None`이면 이번 호출 안에서 새 상태를 수집하므로 먼저 상태 조회 Tool을 부를 필요가 없다. 유효한 ID를 지정하면 그 상태를 기준으로 현재 내용을 읽으며 ID를 교체하지 않는다. 오래된 ID는 거절한다. 내용의 URL·HTML 지문과 관측 상태를 대조하고 변경·이동·닫힘을 확인하면 내용을 성공으로 돌려주지 않는다. 자동 재시도는 없다.

같은 Page를 사용하는 호출은 실행부가 순서대로 수행한다. 예를 들어 `요소 조회 → click → get_page_state(include=["text"], state_id=null)`로 변경된 본문을 읽을 수 있다. **다음 click에 필요한 요소도 함께 얻으려면 include에 elements를 추가한다.** 이전 관측의 element_id를 새 상태에 붙여서 쓰지 않는다. 새 관측은 페이지 새로고침(F5)이 아니며 탭·쿠키·현재 문서는 유지한다.

기존 실행 흐름에는 `tool.as_port()`를 대상 목록에 연결한다. SDK Tool 등록, Agent의 관측 선택, Agent 보고 선별은 연결부의 책임이다.

## 무엇을 읽는가

| 자료 | 범위와 의미 |
|---|---|
| 본문 `text` | 주 문서 body의 브라우저 `innerText`. 스크롤 아래의 문구도 포함한다. 화면 픽셀을 읽는 OCR이 아니다. |
| 링크 `text` | 표시되는 HTML `a[href]`의 `innerText`. 이미지로만 된 링크는 빈 문자열일 수 있다. |
| 링크 `href` | HTML의 실제 href 속성 문자열. 상대 주소와 빈 문자열을 그대로 유지한다. |
| 링크 `resolved_url` | 해당 문서의 기준 주소(`<base>` 포함)로 해석한 주소. 해석 불가는 null이다. 클릭 후 최종 도착 주소가 아니다. |

본문과 링크를 한 번의 동기식 페이지 읽기에서 수집한다. 일반 DOM에서 `display:none`, `visibility:hidden` 등으로 숨겨진 문구를 읽는 HTML 소스 추출기가 아니다. 다만 **투명도·다른 요소의 가림 여부까지 판단하지 않는다.** 기본 선택 상자의 항목 문구 등 브라우저가 `innerText`에 포함하는 텍스트가 나올 수 있다. 입력칸의 현재 value를 별도로 읽거나 이미지의 alt를 본문 대신 만들지 않는다.

iframe 내부, shadow DOM 내부, 이미지 속 글자·캔버스 내용은 지원 범위에 포함하지 않는다. 링크 목록은 `a[href]` 조회이므로 JavaScript 버튼의 이동까지 나열하지 않는다. HTTP 외의 `mailto:` 같은 주소도 원래 속성과 해석 결과를 보존하며 실행하지 않는다. 이 결과만으로 사칭·악성 여부를 판단하지 않는다.

## 반환

기존 공통 반환의 `status`, `started_at`, `finished_at`, `duration_ms`, 상태 ID, `observer_refs`, `error`를 사용한다. 별도 L2/L3 수집은 하지 않으므로 두 observer_refs 목록은 비어 있다. 성공 시 기본 페이지 상태에 아래 본문·링크 항목을 더한다. text/links를 모두 요청하지 않으면 본문 수집을 실행하지 않고 이 추가 항목들도 붙이지 않는다.

| 필드 | 뜻 |
|---|---|
| `page_id`, `state_id` | 읽은 Page와 이번 내용의 기준 관측 |
| `url`, `observed_at` | 수집 당시 주소와 UTC 시각 |
| `observation_scope` | `main_document_light_dom` |
| `text` | 반환된 본문 앞부분. 요청하지 않았으면 null |
| `text_total_bytes` | 제한 적용 전 본문의 UTF-8 바이트 수. 미요청이면 null |
| `text_truncated` | 본문 한도 때문에 일부가 빠졌는지. 미요청이면 null |
| `links` | 문서 순서로 반환된 링크 앞부분. 각 항목은 text/href/resolved_url. 미요청이면 null |
| `links_total` | 조회 범위에 있는 표시 링크의 전체 개수. 미요청이면 null |
| `links_bytes` | 반환된 링크 배열의 공백 없는 JSON UTF-8 바이트 수. 괄호·따옴표·이스케이프 포함. 미요청이면 null |
| `links_truncated` | 개수 또는 바이트 한도 때문에 링크가 빠졌는지. 미요청이면 null |

본문은 UTF-8 문자 중간을 자르지 않는다. 링크는 한 항목을 쪼개지 않으며 한도를 넘는 항목부터 이후 목록을 생략한다. 첫 링크부터 너무 크면 `links=[]`, `links_total>0`, `links_truncated=true`가 된다. 실제 링크가 없는 페이지의 `links=[]`, `links_total=0`, `links_truncated=false`와 구분된다.

두 종류의 생략 표시는 독립적이다. `text`만 요청하면 링크 관련 항목은 모두 null이며 링크가 없다는 뜻이 아니다. 바이트 한도는 본문 문자열과 링크 배열에 각각 적용되며 메타데이터를 포함한 전체 Tool 반환의 크기 한도는 아니다.

읽기 실패에는 `result=null`과 오류를 반환한다. 대표 오류는 `STATE_CHANGED`, `PAGE_CLOSED`, `BROWSER_CRASH`, `ACTION_TIMEOUT`, `INTERNAL_ERROR`, `INVALID_PAGE_TEXT`다. 시간 초과는 `status=timeout`, 나머지는 `failed`이며 닫힘·충돌은 recoverable=false다. 요청 형식·설정 오류는 실행 전에 예외로 거절한다. 호출 취소는 CancelledError로 전달한다.

상태 수집은 PageState의 제한 시간, 본문·링크 수집은 PageContentReader의 제한 시간을 사용한다. 시간 초과·취소가 브라우저 프로세스의 작업 중단을 보장하지는 않으며 늦게 도착한 읽기 결과를 성공으로 반환하지 않는다. Tool이 Page를 닫거나 새로 만들지 않는다.

## 기록과 검증 범위

이 Tool은 조회한 내용을 즉시 반환하며 파일을 저장하지 않는다. 한도로 생략한 원문도 자동으로 따로 보관하지 않는다. 2026-10-02 추가된 [export_page](EXPORT_PAGE.md)는 별도 요청으로 현재 DOM HTML을 파일로 확보해 Bash로 조사하게 한다. 과거 get_page_content 호출 시점의 본문이 자동 보존됐다는 뜻은 아니다. 실제 Tool 입력·반환을 ACT/Store에 연결하고 실행 Agent의 조사 결과에서 총괄에게 필요한 내용을 고르는 책임은 SDK/실행부에 있다.

공개 입력은 `tools/get_page_state.py`, 내부 수집기는 `page_content.py`, 브라우저 읽기는 `_browser/page_content.js`, 본문 검사는 `tests/test_page_content.py`다. 내부 수집기·지원 JS는 추가 Tool이 아니다. 현재 검사는 통합 도구를 호출한다.

## 통합 전 검증 기록

아래 수치·해시는 당시의 별도 본문 Tool 검사 기록이다. 통합 후 실제 결과는 [이번 변경의 검증 자료](../output/l4-page-query-consolidation-20261002/)에 보관한다.

2026-10-01 Windows headless Edge·통제된 로컬 HTTP 페이지에서 새 검사 **21 passed (32.73s)**를 확인했다. 같은 Page의 실제 클릭 전후 본문·주소, 쿠키 유지, 숨김·빈 내용, iframe/shadow 범위, 링크 기준 주소, 한글·emoji 및 링크 JSON 한도, 오래된 관측과 조회 사이의 DOM 변경·이동·닫힘을 확인했다. 시간 초과·취소는 응답 없는 통신을 주입해 검사했으며 실제 브라우저 충돌 재현은 아니다.

실제 페이지 원문 → Tool 반환 → as_port → 기존 flow → 다음 시험용 총괄 입력을 대조하고 원문 보존을 확인했다. 이 전달 검사는 모든 실행 Agent의 Tool 결과를 총괄에게 자동 전달하는 정책이 아니다. 실제 모델·SDK 등록·AWS 연동 및 Linux 서버의 브라우저 실행은 이 Tool로 검증하지 않았다.

기존 PageState·요소 조회·관측 갱신·flow의 관련 회귀는 **53 passed (69.94s)**다. 결과 캐시 쓰기 권한 경고 1건이 있었고 검사 실패는 없었다.

독립 검토는 실제 L4 행동→관측 경로, 상태 유효성, 반환량·생략 표시, Tool 책임범위를 대상으로 했다. 공식 핵심 10개와 별도 작성한 fill→조회 1개에서 **11 passed (21.19s)**를 확인했다. 실제 입력1회 뒤 동일 Page·쿠키를 유지했고, 이전 ID는 STATE_CHANGED/result:null이었다. 새 관측은 원문77바이트 중 `확인 `7바이트를 text_truncated=true로 반환하고 변경된 링크1개/162바이트는 생략 없이 반환했다. 같은 새 ID로 링크만 다시 읽으면 ID를 유지하고 미요청 본문은 null이었다. 읽기 전후 HTML도 동일했다. 구현 측이 [실제 반환 자료](.test-tmp/content-review-2b85f3c4-34dc-4e7e-8eb5-cbf5e9e9aba8/fill-content-evidence.json)와 [독립 재현 코드](.test-tmp/content-review-2b85f3c4-34dc-4e7e-8eb5-cbf5e9e9aba8/test_independent_content.py)를 열어 대조했다. 이는 로컬 시험 산출물이며 서비스의 자동 저장이 아니다.

검토자는 프로젝트의 실제 사용 경로에서 수정 필수 문제를 발견하지 못했다. 원21개 전체 또는 기존53개를 독립적으로 재실행했다는 뜻은 아니다. 검토 전후 일치한 SHA256은 다음과 같다.

| 파일 | SHA256 |
|---|---|
| tools/get_page_content.py | 2F3CC1A9C14B3A7D143848CA5EDC4605D911D6D12EF56EB47469218EF4896E61 |
| _browser/page_content.js | 57BB4E479C1144B66987BFFB69F6F6CD9EAC55E6349821B450EBEC62F941E401 |
| tests/test_page_content.py | A76699A68CE6692F7670AB3ED67A94846295D19F6B9C82AB99059FD240EACE8B |
