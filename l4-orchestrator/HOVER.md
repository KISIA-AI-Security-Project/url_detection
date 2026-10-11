# hover — 조회한 요소 위에 포인터 올리기

현재 SDK 연결은 [AGENTS_SDK.md](AGENTS_SDK.md)를 따른다. 아래 날짜가 붙은 초기 검증 기록은 당시 범위이며, 현재 실행 검사 결과는 [정리 검증 기록](../output/l4-sdk-cleanup-20261002/)에서 확인한다.

2026-09-28 승인한 범위: 기존 요소 조회에서 ID를 받은 요소에 마우스를 올린다. 같은 Page·ElementRegistry·PageState·PageEvents를 사용하며 현재 화면 안의 대상에 한정한다. 구현은 `src/l4_orchestrator/tools/hover.py`의 `HoverTool`이다.

## 실제 조사에서 쓰는 흐름

서비스 버튼에 마우스를 올리면 하위 메뉴가 나타나고, 그 안의 다운로드 버튼을 클릭하는 상황을 다룬다.

`서비스 버튼 조회 → hover → 새 메뉴 요소 조회(state_id=null) → 다운로드 버튼 click`

hover 대상과 click 대상은 다를 수 있다. 설명창만 읽고 클릭하지 않는 조사도 가능하다. 같은 Page와 포인터를 유지하며, hover 반환 뒤 포인터를 원래 위치로 되돌리지 않는다. 상태 갱신과 요소 조회도 포인터를 움직이지 않으므로 연속 동작을 구성할 수 있다. 사이트 자체가 메뉴를 닫거나 요소를 교체할 수 있으므로 메뉴의 무기한 유지까지 보장하지는 않는다.

두 Tool을 분리하면 중간 관측으로 다음 대상을 고를 수 있고, 실패가 마우스 올리기 단계인지 클릭 단계인지 구분된다. 반면 중간에 실제 모델 판단을 넣으면 그만큼 호출 시간과 비용이 들 수 있다. Tool 분리 자체가 매 동작마다 별도 모델 호출을 강제하지는 않지만, 현재 실제 실행 Agent의 호출 순서·판단 정책은 아직 연결 전이다. hover와 click을 자동으로 묶는 기능은 이번 구현에 추가하지 않았다.

## 입력

```json
{
  "action_id": "hover-1",
  "tool": "hover",
  "target": {"element_id": "현재 요소 조회에서 받은 ID"},
  "params": {},
  "context": {
    "job_id": "현재 조사 ID",
    "scenario_id": "현재 시나리오 ID",
    "step_id": "메뉴 확인 단계 ID",
    "state_id": "현재 관측 ID"
  }
}
```

`element_id`는 좌표나 CSS 선택자가 아니라 기존 ElementRegistry가 실제 노드에 발급한 ID다. 다른 Page·예전 관측·삭제된 노드를 대신해 비슷한 요소를 다시 찾지 않는다. `state_id: null`은 현재 유효한 관측을 사용한다는 뜻이며, 관측 없이 실행한다는 뜻은 아니다.

현재 요소 조회가 지원하는 native 버튼·링크·입력 등과 지원 ARIA 역할의 요소가 대상이다. 일반 div에만 연결된 모든 hover 동작을 자동 발견하거나 iframe·shadow DOM으로 범위를 넓히지 않았다. 추가 동작을 뜻하는 `click_after`, `force`, `scroll` 등의 입력은 거절한다.

## 내부 처리

1. 입력, 현재 관측, 최신 요소 목록에 등록된 동일 노드를 확인한다.
2. 숨김 여부와 현재 viewport와의 교차를 확인한다. 화면 밖 요소에는 `ELEMENT_NOT_VISIBLE`을 반환한다.
3. 시도 직전에 기존 PageState를 무효화한다. CSS `:hover`로 화면만 달라지고 DOM 원문은 그대로일 수 있기 때문이다.
4. 같은 노드에 `hover(force=False, scroll="none")`를 한 번 호출한다. Playwright가 가림·안정성·포인터 도달 가능성을 확인하며, 내부 상자를 포함한 자동 스크롤은 하지 않는다.
5. 동작 완료 또는 실패를 반환하고 임시 노드 참조와 사건 수집 구간을 정리한다. 포인터를 이동 전 위치로 되돌리지는 않는다.

클릭과 달리 `disabled`·`aria-disabled`만으로 거절하지 않는다. 비활성 버튼에도 CSS 설명창이 붙을 수 있기 때문이다. 이것이 가려진 요소나 inert 영역을 강제로 조작한다는 뜻은 아니다. 실제 포인터가 도달할 수 있어야 한다.

이동으로 발생한 사이트의 DOM 반응과 지연된 메뉴 표시는 후속 관측에서 확인한다. `hover` 안에서 전체 DOM 차이를 새로 수집하거나 메뉴 표시 완료까지 임의로 기다리지 않는다. 사이트 자체가 hover 반응으로 이동이나 네트워크 요청을 일으킬 수 있으며 네트워크 정책은 실행 환경이 담당한다.

## 결과와 상태

```json
{
  "element_id": "조회한 ID",
  "hovered": true,
  "page_events": [],
  "event_scope": "hover_call_interval"
}
```

위는 공통 반환의 `result` 부분이다. `hovered: true`는 Playwright의 포인터 이동 동작이 완료됐다는 뜻이며, 메뉴 생성·설명창 표시·조사 질문 해결의 확인은 아니다. 시도 전 거절은 false, 시도 후 시간 초과·실패로 완료를 확인할 수 없으면 null이다. 시간 초과여도 실제 포인터는 이동했을 수 있으므로 자동 재시도하거나 원위치로 되돌리지 않는다. 외부 취소는 취소로 전파하고 참조·사건 수집 구간을 정리한다.

공통 결과는 상태·시각·오류와 `before_state_id`를 포함한다. hover 안에서는 자동 재관측을 하지 않아 `after_state_id`는 null이고 `observer_refs`는 빈 목록이다. 이후 `get_page_state(params.include=["elements"], context.state_id=null)` 조회가 새 관측과 요소 목록을 얻고, 그 반환 ID로 click을 연결한다. 이전 관측 ID로 바로 click하면 거절된다.

PageEvents는 실행 환경이 같은 Page 수명 동안 유지한다. 호출 구간에 관측한 이동·새 탭은 이 Tool 결과에 포함되고, 반환 뒤 늦게 발생한 사건은 지속 연결을 통해 실행 환경에 전달된다. 늦은 사건을 과거 action_id로 자동 귀속하지 않는다.

Tool이 별도 파일·스크린샷을 만들지 않는다. SDK 연결이 입력과 반환을 Store에 기록하고, 작업 결과 전달은 `review_after`를 따른다.

## 연결

```python
hover = HoverTool(
    elements,
    timeout_ms=settings.hover_timeout_ms,
    page_events=page_events,
)
native_tools["hover"] = hover  # register_native_tools에 전달
```

설정값과 실행 환경은 호출측이 제공하며, timeout은 양의 정수다. 공유 Page의 동작·refresh·조회는 순차로 실행한다. 운영 제한 시간과 실제 모델 정책을 Tool이 임의로 정하지 않는다.

## 검증

`tests/test_hover.py`는 실제 Edge와 통제된 로컬 페이지에서 아래를 확인한다.

- CSS만 바뀌는 메뉴, 새 DOM 메뉴, native/ARIA 비활성 버튼의 설명창
- hover만으로 클릭하지 않음, 포인터·Page 유지, refresh·재조회 후 다른 하위 메뉴 click
- 기존 상태로 click 거절, 관측 뒤 교체된 메뉴를 대신 클릭하지 않음
- 숨김·화면 밖·가림·오래된 요소, 내부 스크롤 영역을 자동 이동하지 않음
- 실제 포인터 이동 뒤 timeout·취소 시 반복·되돌림 없음과 정리
- 늦은 페이지 이동 알림, 닫힌 Page, 잘못된 입력·설정, 기존 flow에 실제 반환 전달

최종 코드의 표적 검사 **20 passed (27.75s)**, 기존 검사를 포함한 전체 **170 passed (171.63s)**. 독립 검토자는 동일 고정본의 실제 Edge 핵심 **8 passed (12.76s)**를 확인했다. 실제 실행 Agent의 판단·모델 대화 문맥 연결·외부 사이트 조사·AWS 진행 API는 이번 검증 범위가 아니다.
