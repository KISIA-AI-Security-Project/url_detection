# select_option — 기본 선택 상자의 항목 선택

현재 SDK 연결은 [AGENTS_SDK.md](AGENTS_SDK.md)를 따른다. 아래 날짜가 붙은 초기 검증 기록은 당시 범위이며, 현재 실행 검사 결과는 [정리 검증 기록](../output/l4-sdk-cleanup-20261002/)에서 확인한다.

HTML 기본 `<select>`에서 항목 하나를 선택한다. 예를 들어 국가 선택 상자를 `선택하세요`에서 `대한민국`으로 바꾼다. 사이트가 버튼과 목록으로 직접 만든 메뉴와 `multiple` 선택 상자는 이번 Tool 대상에서 제외한다.

## 우리 흐름에서 쓰는 순서

1. `get_page_state(params.include=["elements"], context.state_id=null)`로 선택 상자와 그 항목 목록을 읽는다.
2. Agent가 항목을 결정하고 반환된 `element_id`, `state_id`와 선택 기준 하나를 전달한다.
3. Tool이 같은 선택 상자와 항목을 확인하고 한 번 선택한다.
4. 실제 선택 상태를 확인해 결과를 반환한다. 이후 새 입력칸 등이 필요하면 다시 요소를 조회한다.

선택할 항목의 의미나 다음 행동은 Agent가 결정한다. Tool은 별도 촬영·파일 저장·자동 재시도를 수행하지 않는다. SDK 연결이 Store에 요청·반환을 기록한다.

## 입력

```json
{
  "action_id": "choose-country",
  "tool": "select_option",
  "target": {"element_id": "요소 조회에서 받은 ID"},
  "params": {"value": "KR"},
  "context": {
    "job_id": "분석 ID",
    "scenario_id": "조사 ID",
    "step_id": "단계 ID",
    "state_id": "요소 조회에서 받은 관측 ID"
  }
}
```

`params`에는 아래 중 **정확히 하나**만 지정한다. 여러 기준이나 여러 항목의 배열은 받지 않는다.

| 입력 예 | 의미 |
|---|---|
| `{"value": "KR"}` | 항목의 실제 값이 정확히 KR인 항목 |
| `{"label": "대한민국"}` | 표시 이름이 정확히 대한민국인 항목 |
| `{"index": 1}` | 전체 옵션 목록의 두 번째 항목. 순서는 0부터 시작하며 optgroup 안의 항목도 포함 |

빈 문자열 value도 유효하다. label의 부분 일치나 임의 공백 정리는 하지 않는다. 같은 value·label이 여러 항목과 일치하면 임의의 첫 항목을 선택하지 않고 `BLOCKED_ACTION`으로 거절한다. 이 경우 조회 결과의 index로 구분할 수 있다. index에는 정수만 받으며 bool·문자열·음수는 거절한다.

`context.state_id=null`은 행동 Tool의 기존 규칙대로 현재 유효한 관측을 사용한다는 의미다. 새 관측을 자동으로 수집한다는 뜻은 아니다. 오래된 관측·다른 페이지·등록되지 않은 요소는 실행 전에 거절한다.

## 선택할 항목을 Agent가 아는 방법

기존 요소 조회 결과 중 native select에만 아래 정보를 추가했다. 다른 요소의 반환 형태와 input·textarea 값 미반환은 유지한다.

```json
{
  "element_id": "el_example",
  "role": "combobox",
  "name": "국가",
  "text": "선택하세요 대한민국",
  "visible": true,
  "enabled": true,
  "multiple": false,
  "options": [
    {"index": 0, "value": "", "label": "선택하세요", "enabled": true, "selected": true},
    {"index": 1, "value": "KR", "label": "대한민국", "enabled": true, "selected": false}
  ]
}
```

위 값은 설명용 예시다. 구현은 조회 시점의 실제 option 속성을 읽는다. `enabled`에는 선택 상자와 option·optgroup의 disabled, 가장 가까운 aria-disabled true/false 및 inert를 반영한다. `selected`는 현재 선택 속성이다. 이 정보는 관측 시점의 값이며 이후 페이지가 바꾸지 않는다는 보장이 아니다.

## 내부 동작과 결과

기존 ElementRegistry로 정확한 select 노드를 확인한다. native 단일선택 여부, 표시 여부, 활성 상태, 요청에 맞는 항목 하나와 그 항목의 활성 상태를 검사한다. 선택 직전에 기존 PageState를 무효화한다.

Playwright에 **그 option 노드 자체**를 전달한다. 같은 값·이름을 가진 새 노드를 다시 찾지 않는다. 선택 뒤에도 같은 select와 option이 연결되어 있고 해당 option만 선택되어 있으며 확인한 value가 유지되는지 검사한다.

```json
{
  "element_id": "el_example",
  "selected": true,
  "selected_value": "KR",
  "page_events": [],
  "event_scope": "select_option_call_interval"
}
```

| selected | 의미 |
|---|---|
| true | 선택 호출 뒤 같은 항목이 선택된 상태를 확인함 |
| false | 사전 검사에서 거절되어 선택 호출을 시도하지 않음 |
| null | 선택을 시도했으나 완료 상태를 확인하지 못함. 이미 선택되었거나 사이트 반응이 발생했을 수 있음 |

`selected_value`는 true일 때 확인한 실제 값이다. 실패·시간 초과에는 null이며, 단순히 요청 값을 성공 결과처럼 복사하지 않는다. 사이트의 change 처리기가 선택을 되돌리거나 노드를 교체하면 성공으로 표시하지 않는다. 성공도 그 확인 시점의 상태이며, 사이트 전체 처리 완료나 URL의 안전성을 뜻하지 않는다.

공통 반환의 `before_state_id`는 행동 전에 확인한 관측 ID, `after_state_id`는 null이다. 다음 null 조회가 새 관측을 얻는다. 이전 결과를 소급 갱신하지 않는다. PageEvents는 같은 페이지의 이동·새 탭 사건을 기존 방식으로 전달하고, Tool에는 호출 구간에 관측한 사건만 포함한다.

Playwright의 select_option은 선택 속성을 바꾸고 input/change 사건을 발생시킨다. 실제 마우스로 운영체제의 드롭다운을 열어 고르는 방식이나 trusted 입력 재현으로 설명하지 않는다. 이미 선택된 항목을 다시 요청해도 이 사건이 발생할 수 있다. Tool이 제출 명령을 추가하지는 않지만 사이트의 사건 처리기가 이동·제출 등을 일으킬 수 있다. 네트워크·팝업 정책은 기존처럼 실행 환경의 책임이다.

사전 검사와 브라우저 동작 사이 사이트의 모든 변화를 원자적으로 막는 기능은 아니다. 선택 상태를 확인할 수 없는 결과는 null로 남기며 임의로 재선택하거나 되돌리지 않는다.

## 연결

```python
from l4_orchestrator.tools.select_option import SelectOptionTool

tool = SelectOptionTool(
    elements,
    timeout_ms=action_timeout_ms,
    page_events=page_events,
)
native_tools["select_option"] = tool  # register_native_tools에 전달
```

ElementRegistry와 PageEvents는 같은 PageState를 공유한다. 제한 시간은 호출측이 제공하며 같은 Page의 작업은 순차로 실행한다. `execute()` 직접 호출과 기존 실행 접점 `as_port()`를 모두 지원한다. 고정 기능 분류는 `new_observation`이다.

## 검증 범위

`tests/test_select_option.py`에서 실제 headless Edge와 통제된 로컬 페이지로 값·이름·순서 선택, 항목 관측, 비활성·없는 항목·중복 거절, 같은 값의 항목 교체, change 처리기의 되돌림, 시간 초과·취소·종료와 기존 flow의 원입력·반환·후속 입력을 대조한다. 선택으로 나타난 입력칸을 새로 조회해 fill로 이어지는 동작도 검사한다. 충돌은 콜백 주입으로 검사하며 실제 브라우저 충돌 재현과 구분한다. 실행 결과는 README의 최신 절에 기록한다.

기준: [프로젝트 select_option 명세](https://l4-browser-tool-spec-light-pages.vercel.app/#/select-option), [Playwright ElementHandle.select_option](https://playwright.dev/python/docs/api/class-elementhandle#element-handle-select-option). 일반적으로 Locator가 권장되지만, 이 프로젝트는 관측한 동일 노드만 사용하고 교체 노드를 다시 찾지 않기 위해 기존 ElementHandle 방식을 유지한다.
