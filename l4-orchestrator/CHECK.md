# check — 체크박스·라디오 버튼을 선택된 상태로 만들기

현재 SDK 연결은 [AGENTS_SDK.md](AGENTS_SDK.md)를 따른다. 아래 날짜가 붙은 초기 검증 기록은 당시 범위이며, 현재 실행 검사 결과는 [정리 검증 기록](../output/l4-sdk-cleanup-20261002/)에서 확인한다.

`src/l4_orchestrator/tools/check.py`는 조회한 **native HTML `<input type="checkbox">` 또는 `<input type="radio">`**를 선택한다. 일반 click은 체크박스를 반대로 토글하지만 check는 이미 선택된 항목을 다시 누르지 않는다. 같은 브라우저·Page·요소 등록부를 사용한다.

## 입력과 실제 사용 흐름

먼저 `get_page_state`에 `params.include=["elements"]`를 주어 현재 요소를 조회하고, 반환된 `element_id`와 `state_id`를 사용한다.

```json
{
  "action_id": "show-details-1",
  "tool": "check",
  "target": {"element_id": "el_example"},
  "params": {},
  "context": {
    "job_id": "analysis-example",
    "scenario_id": "inspect-form",
    "step_id": "show-details",
    "state_id": "state_example"
  }
}
```

위 ID는 설명용이다. `params`는 빈 객체만 받으며 `checked:false`, force, 선택 해제 등 다른 입력은 허용하지 않는다. `context.state_id=null`은 기존 행동 Tool과 동일하게 현재 유효한 관측을 사용한다는 뜻이다. 자동으로 새 관측을 수집하지 않는다.

요소 조회에 native checkbox/radio의 현재 `checked`를 추가했다. checkbox에는 `indeterminate`도 함께 반환한다. 이는 HTML에 처음 적힌 checked 속성이 아니라 조회 시점의 실제 DOM 속성이다. input 값은 반환하지 않는다. 사용자 정의 ARIA checkbox/radio에는 이 새 필드를 붙이지 않으며 check 대상으로 지원하지 않는다.

`indeterminate:true`는 보통 체크 대신 `−`로 표시되는 중간 상태다. 현재 check는 이 상태를 변경하지 않고 `BLOCKED_ACTION`으로 거절한다. `.checked=true`와 중간 상태가 동시에 성립할 수 있으므로 두 값을 혼동하지 않는다.

## 동작과 결과

1. 현재 관측과 정확한 요소 노드를 확인한다. 교체된 노드를 같은 이름으로 다시 찾지 않는다.
2. native 타입, 표시·활성 상태, 중간 상태 여부를 확인한다. 이미 체크돼 있어도 숨김·비활성 대상은 거절한다.
3. 이미 체크돼 있으면 상태를 다시 확인한 뒤 **클릭 없이 success**를 반환한다. 입력 사건을 발생시키거나 관측을 무효화하지 않는다.
4. 체크되지 않았다면 기존 PageState를 무효화하고 같은 노드의 Playwright `check(force=False)`를 한 번 호출한다. 브라우저의 동작 가능 조건을 기다리며 필요하면 대상까지 스크롤할 수 있다.
5. 같은 노드가 문서에 남아 있고 입력 타입이 유지되며 실제 체크 상태가 true인지 확인한다. checkbox가 중간 상태가 된 경우도 거절한다.

라디오를 선택하면 브라우저가 같은 그룹의 다른 라디오 선택을 해제할 수 있다. 그래서 실제 시도에서는 전체 PageState를 무효화한다. 이후 `get_page_state(params.include=["elements"], context.state_id=null)`로 새 목록을 받으면 그룹의 변경 상태와 새로 나타난 입력칸 등을 확인할 수 있다.

공통 ToolResult 안의 result 예시는 다음과 같다.

```json
{
  "element_id": "el_example",
  "checked": true,
  "page_events": [],
  "event_scope": "check_call_interval"
}
```

- `checked:true`: 이미 체크돼 있거나 동작 후 확인된 체크 상태. 사이트 전체 처리가 끝났다는 뜻은 아니다.
- `checked:null`: 실패·시간 초과로 성공을 확인하지 못했다. 체크되지 않았다는 뜻이나 입력이 전혀 없었다는 뜻이 아니다. 사전 거절에서도 false를 만들어내지 않는다.
- `status`, `error.code`로 성공·거절·시간 초과를 구분한다. 실제 변경 후 응답 오류가 나도 성공으로 승격하거나 재시도하지 않는다.
- `before_state_id`: 행동 전에 확인한 관측 ID. 무클릭 성공의 `after_state_id`는 같은 ID이며 새 관측을 만든 것이 아니다. 실제 시도 뒤에는 null이다.

선택을 즉시 되돌리는 사이트 처리기, 노드 교체, 타입 변경은 성공으로 표시하지 않는다. 성공은 최종 확인 시점의 상태이며 이후 사이트의 비동기 변경까지 막지 않는다. 사전 검사와 브라우저 입력 사이의 모든 변화를 원자적으로 막는 기능도 아니다.

Tool이 제출 명령을 추가하지 않지만 사이트의 input/change/click 처리기가 이동·팝업·제출 등을 발생시킬 수 있다. 기존 PageEvents 연결부로 사건을 전달하며 Tool 반환에는 호출 구간 사건만 담는다. 늦은 사건 처리는 기존 호출측 연결을 사용한다. 네트워크·팝업 정책, 같은 Page의 순차 사용은 실행 환경의 책임이다.

## 기존 실행 접점 연결

```python
from l4_orchestrator.tools.check import CheckTool

tool = CheckTool(elements, timeout_ms=action_timeout_ms, page_events=page_events)
native_tools["check"] = tool  # register_native_tools에 전달
```

ElementRegistry와 PageEvents는 동일 PageState를 공유해야 한다. 시간 제한은 호출측이 제공한다. 직접 `execute()`하거나 SDK의 `register_native_tools`에 연결할 수 있다. 고정 기능 분류는 `new_observation`이며 이미 체크된 무입력 성공도 실제 DOM을 확인한다.

별도 상세 파일·촬영·자동 재조회·자동 재시도·선택 해제·사용자 정의 위젯 처리는 추가하지 않는다. SDK로 호출하면 입력·반환이 Store에 남고 작업 결과 전달은 `review_after`를 따른다.

## 검증 범위

`tests/test_check.py`는 실제 headless Edge와 통제된 로컬 페이지에서 선택·무클릭 유지·라디오 그룹·현재 속성 관측·비활성/숨김/중간 상태 거절·오래된 대상·사이트 되돌림/교체/타입 변경·가려진 대상 시간 초과·실제 변경 후 응답 오류·취소 정리·종료 사건을 검사한다. crash는 콜백 주입이며 실제 브라우저 충돌과 구분한다.

조회 결과 → 요청 → 실제 체크 → flow의 원입력·반환 → 후속 시험용 총괄 입력을 대조하고, 새 조회로 나타난 입력칸에 fill을 이어가는 검사도 포함한다. 실제 Agent 판단, 외부 의심 사이트, AWS·사용자 진행 화면의 운영 검증은 아니다. 최신 실행 결과는 README에 기록한다.

기준: [프로젝트 check 명세](https://l4-browser-tool-spec-light-pages.vercel.app/#/check), [Playwright ElementHandle.check](https://playwright.dev/python/docs/api/class-elementhandle#element-handle-check). 일반적인 Playwright 사용에는 Locator가 권장되지만 이 프로젝트는 관측한 동일 노드만 사용하기 위해 기존 ElementHandle 방식을 유지한다.
