# wait_for — 필요한 조건까지 제한 시간 안에서 기다리기

현재 SDK 연결은 [AGENTS_SDK.md](AGENTS_SDK.md)를 따른다. 아래 날짜가 붙은 초기 검증 기록은 당시 범위이며, 현재 실행 검사 결과는 [정리 검증 기록](../output/l4-sdk-cleanup-20261002/)에서 확인한다.

`src/l4_orchestrator/tools/wait_for.py`는 기존 Page에서 여섯 가지 조건 중 하나를 기다린다. 대기가 끝나면 해당 조건의 확인 결과를 반환한다. 각 행동 뒤 무조건 기다리도록 만들지는 않는다.

예를 들어 `요소 조회(숨김 포함) → select_option으로 국가 선택 → wait_for로 기존 지역 입력칸 visible 대기 → 새 요소 조회 → fill`로 이어진다. 클릭·선택 이후 늦게 바뀌는 요소를 기다릴 때 중간에 비교 기준을 새로 만들 필요가 없다.

## 입력

```json
{
  "action_id": "wait-region-1",
  "tool": "wait_for",
  "target": {"element_id": "el_region_example"},
  "params": {"condition": "visible", "timeout_ms": 3000},
  "context": {
    "job_id": "analysis-example",
    "scenario_id": "inspect-form",
    "step_id": "wait-region",
    "state_id": "state_before_selection_example"
  }
}
```

예시 ID는 실제 조회 결과로 바꾼다. 여기서 원래 요소란 그 조회에서 받은 실제 버튼·입력칸을 말한다. 같은 이름의 새 버튼이 대신 생겨도 다른 대상이다. 아직 숨겨진 기존 요소를 대상으로 하려면 `get_page_state`에 `params={"include":["elements"],"visible_only":false}`를 주어 미리 등록해야 한다. 아직 생성되지 않은 요소, 일반 스피너 div, iframe·shadow DOM 내부는 현재 요소 조회의 범위 밖이며 이 Tool이 selector로 새로 찾아내지 않는다.

| condition | target | 의미 |
|---|---|---|
| visible | 기존 element_id | 원래 요소가 표시됨 |
| hidden | 기존 element_id | 원래 요소가 숨겨지거나 같은 문서에서 제거됨 |
| url_change | null | 최근 기준 관측의 URL과 현재 Page URL이 다름 |
| dom_change | null | 최근 기준 관측과 현재 주 문서의 outerHTML 해시가 다름 |
| load_state | null | 현재 문서가 지정한 로딩 단계에 도달함 |
| timeout | null | 지정한 시간 경과. 화면 준비 완료는 의미하지 않음 |

`load_state`에만 `params.state`를 추가로 받을 수 있다. `"domcontentloaded"` 또는 `"load"`이며 생략 시 `"load"`다. 현재 문서가 해당 단계에 이미 도달했으면 바로 반환한다. 앞으로 시작할 페이지 이동을 예측해 기다리지 않는다. networkidle은 이번 범위에 넣지 않았다.

`params.timeout_ms`는 필수 양의 정수이며 bool·문자열·0은 거절한다. 실행 환경이 제공한 `max_timeout_ms`보다 크면 `status:blocked`, `error.code:BLOCKED_ACTION`으로 거절하고 요청을 임의로 줄이지 않는다. 조건 대기의 시간 한도에는 원노드 확인과 반복 확인도 포함된다. 고정 시간 경과는 일반 TimeoutError를 성공으로 바꿔서 처리하지 않는다. 반환·정리 시간은 대기 시간과 별개로 소량 추가될 수 있다.

## 비교 기준과 행동용 상태

기존 행동 Tool은 입력 시도 전 PageState를 무효화한다. 이제 PageState가 가장 최근 성공 관측 **한 개의 메타데이터**를 메모리에 비교용으로 유지한다. 원본 HTML 파일이나 과거 관측 전체 이력을 저장하지 않는다.

- visible/hidden/url_change/dom_change에는 기준 관측이 필요하다. `context.state_id`로 최근 관측을 지정한다. null이면 최근 비교 기준을 사용하며 새 관측을 수집하지 않는다. 기준이 없거나 이미 교체된 ID면 TARGET_STALE다.
- URL·HTML 변화가 Tool 호출 전에 이미 발생했어도 그 기준과 현재가 다르면 조건을 확인할 수 있다.
- 새 관측 수집을 시작하면 기존 비교 기준을 폐기한다. 수집 실패·취소 뒤에도 옛 기준을 복구하지 않는다. 새 성공 관측이 다음 기준이 된다.
- 요소 대기는 그 기준의 마지막 성공 요소 조회에서 등록한 ID만 받는다. 새 상태만 조회했거나 요소 조회가 실패했다면 옛 요소 목록을 새 기준의 목록으로 재사용하지 않는다.
- load_state/timeout은 기준 없이도 수행할 수 있다. 이때 context.state_id는 null이다. 명시 ID를 제공했다면 그 비교 기준이 여전히 최신이어야 한다.

`PageState.read_comparison()`과 `ElementRegistry.resolve_for_wait()`는 대기를 위한 별도 읽기 경로다. 기존 행동용 `read()`·`resolve()`는 계속 유효한 최신 상태를 요구한다. 비교용 기준을 보존했다고 오래된 ID로 click/fill/select_option을 실행할 수 있게 되지는 않는다.

같은 문서의 pushState 등 주소 변경 뒤에도 원래 요소를 기다릴 수 있다. 실제 문서가 교체되면 visible/hidden은 TARGET_STALE다. url_change/dom_change는 페이지 이동 뒤에도 기준과 현재를 비교할 수 있다.

## 조건의 한계와 반환

요소의 visible은 연결된 원노드의 크기와 CSS visibility를 확인한다. opacity 0이나 viewport 밖 상태를 별도의 숨김으로 판정하지 않는다. 보이는 요소가 클릭 가능·활성·가림 없음까지 보장하는 것은 아니다.

hidden에서 원노드 제거를 확인해도 같은 이름의 교체 요소가 사라졌다는 뜻은 아니다. visible에서는 원노드 제거를 TARGET_STALE로 반환한다. 페이지 종료·충돌을 원노드 제거로 바꿔 hidden 성공을 만들지 않는다.

dom_change는 HTML 구성 차이다. 단순 관측 무효화, viewport 크기 변경, `.checked` 같은 DOM 속성만의 변화, HTML이 동일한 reload는 충족시키지 않는다. 해당 조사에 필요한 정보가 나타났다는 의미도 아니다. 약 50ms 간격과 실제 읽기 시간으로 현재 조건을 반복 확인하며 모든 순간의 변화 이력을 기록하지 않는다. HTML이 잠깐 바뀌었다가 돌아오는 경우 등은 확인하지 못할 수 있다. 이동이 HTML 읽기를 중단했다는 것이 확인되면 같은 시간 한도 안에서 다음 확인을 수행한다.

공통 ToolResult 안의 result 예시는 다음과 같다.

```json
{
  "condition": "visible",
  "satisfied": true,
  "page_events": [],
  "event_scope": "wait_for_call_interval"
}
```

`satisfied:true`는 그 조건을 확인했다는 뜻이다. 실패·시간 초과는 null이며 확인 시점 이후에도 조건이 유지된다는 보장이나 페이지 전체 처리 완료를 뜻하지 않는다. 상태·오류코드로 한도 초과, 기준/대상 문제, 조건 시간 초과, 종료/충돌을 구분한다.

`before_state_id`는 사용한 비교 기준 ID이며 기준 없는 요청에서는 null이다. 수락한 대기는 기존 행동용 상태를 무효화하고 `after_state_id:null`을 반환한다. 완전한 새 관측을 만든 것이 아니므로 **다음 행동 전에는 `get_page_state(params.include=["elements"], context.state_id=null)`로 새 상태와 대상 ID를 받는다.**

같은 PageEvents 연결을 이용해 호출 구간의 이동·팝업 사건을 반환하고 늦은 사건도 기존 실행 환경에 전달한다. 호출 구간 사건은 Tool이 사건을 일으켰다는 뜻이 아니다. Tool은 클릭·입력·스크롤·새 탭 선택·제출 명령을 수행하지 않는다. 별도 파일·스크린샷·자동 새 관측·추가 행동 재시도도 만들지 않는다. SDK 연결이 호출 입력과 반환을 Store에 기록한다.

## 연결과 검증

```python
from l4_orchestrator.tools.wait_for import WaitForTool

tool = WaitForTool(elements, max_timeout_ms=wait_limit_ms, page_events=page_events)
native_tools["wait_for"] = tool  # register_native_tools에 전달
```

같은 PageState를 공유한 ElementRegistry와 PageEvents를 사용한다. 전체 Page의 행동·조회·대기는 호출측이 순차로 실행한다. 직접 execute와 기존 실행 접점 as_port를 지원하며 provenance는 new_observation이다. 고정 시간 경과의 의미는 실제 입력 params.condition과 함께 읽어야 한다.

`tests/test_wait_for.py`는 실제 headless Edge·통제된 로컬 페이지에서 여섯 조건, 한도 초과, 같은 문서와 문서 교체, 원노드 제거·교체, 과거 기준 거절, 실패·취소 후 기준 폐기·복구, 시간 초과, 취소 정리와 종료 우선을 검사한다. 실제 select→wait를 기존 flow에 연결해 원입력·반환·후속 시험용 총괄 입력을 대조하고 새 조회→fill까지 확인한다. 이동 알림 전에 HTML 읽기 문맥이 사라지는 경합도 실제 이동과 오류 순서 주입으로 검사했다. 이때만 기존 시간 한도에서 확인을 이어가고 일반 읽기 오류는 즉시 실패한다. 계속되는 문맥 손실도 시간 초과로 끝난다. crash는 콜백 주입이다. 최신 실행 결과는 README에 기록한다.

이 검증은 실제 Agent의 대기 선택, 외부 의심 사이트, AWS·사용자 진행 화면의 운영 검증을 대신하지 않는다. 브라우저 명세의 13개 이름에 해당하는 Tool 모듈이 갖춰졌다는 것과 전체 서비스 완료는 구분한다. Bash Tool과 AWS 신규 기록 조회는 별도 범위다.

기준: [프로젝트 wait_for 명세](https://l4-browser-tool-spec-light-pages.vercel.app/#/wait-for), [Playwright Page.wait_for_load_state](https://playwright.dev/python/docs/api/class-page#page-wait-for-load-state).
