# scroll — 현재 페이지 전체 이동

현재 SDK 연결은 [AGENTS_SDK.md](AGENTS_SDK.md)를 따른다. 아래 날짜가 붙은 초기 검증 기록은 당시 범위이며, 현재 실행 검사 결과는 [정리 검증 기록](../output/l4-sdk-cleanup-20261002/)에서 확인한다.

2026-09-28 사용자 승인 범위: 같은 브라우저 Page의 문서를 상하좌우로 한 번 이동한다. `tools/scroll.py`의 `ScrollTool`을 직접 호출하거나 `register_native_tools`로 SDK에 연결한다. 내부 상자·iframe·새 탭 선택은 이번 범위가 아니다.

## 입력

```json
{
  "action_id": "scroll-1",
  "tool": "scroll",
  "target": null,
  "params": {"direction": "down", "amount": 600},
  "context": {
    "job_id": "현재 조사 ID",
    "scenario_id": "현재 시나리오 ID",
    "step_id": "현재 단계 ID",
    "state_id": "이동 전 관측 ID"
  }
}
```

- `target: null`: 현재 Page의 문서 전체. `{element_id: ...}` 등 내부 영역 입력은 검증 단계에서 거절한다. 페이지 전체로 대신 실행하지 않는다.
- `direction`: `up`, `down`, `left`, `right` 중 하나.
- `amount`: 요청하는 양의 CSS 픽셀 수. 소수도 받을 수 있으며 실제 브라우저 좌표는 반올림·경계·스크롤 스냅 등에 따라 다를 수 있다. 문자열·boolean·0·음수·NaN·Infinity는 거절한다.
- `state_id`: 지정하면 같은 관측인지 확인한다. `null`이면 현재 유효한 PageState를 사용한다. 유효한 관측이 하나도 없으면 먼저 실행 환경에서 `refresh()`해야 한다.

## 내부 동작

1. 입력과 현재 관측을 검사하고 현재 문서의 참조를 잡는다.
2. 실행 환경의 `reserve_attempt(request)`를 한 번 호출한다. 이 함수는 조사별 남은 횟수를 확인하고 허용할 때 한 번 차감한 뒤 기존 `Authorization`을 반환한다. 짧은 동기 함수이며 대기·네트워크 작업을 넣지 않는다.
3. 거절하면 이동과 상태 무효화를 하지 않는다. 허용되면 시도 직전에 이전 PageState를 무효화한다. 화면 범위 변경은 DOM 변경 알림만으로 잡히지 않기 때문이다.
4. Playwright를 통해 해당 문서에 `window.scrollBy`를 한 번 실행한다. 방향을 x/y 증가·감소로 바꾸며 `behavior: instant`를 사용한다. 마우스 아래의 내부 상자에 휠 입력을 보내는 방식이 아니다. [브라우저 API 설명](https://developer.mozilla.org/en-US/docs/Web/API/Window/scrollBy).
5. 실행 환경이 지정한 `wait_ms` 뒤 같은 문서의 실제 좌표를 읽고 이전 좌표와의 차이를 반환한다. 이 시간은 지연 로딩·페이지 반응을 관측하기 위한 제한된 대기이며 모든 로딩 완료를 보장하지 않는다.

같은 URL 재로딩을 포함해 실행 중 페이지 이동이 관측되면 이전·새 문서 좌표를 섞지 않는다. 같은 문서 안의 URL 이동도 보수적으로 `TARGET_STALE`로 처리한다. 일반 DOM 변화는 지연 로딩일 수 있으므로 그 자체를 스크롤 실패로 바꾸지 않는다.

## 반환의 의미

아래는 y=0에서 아래로 600px 이동한 경우의 `result` 예다.

```json
{
  "direction": "down",
  "amount": 600,
  "attempted": true,
  "moved": true,
  "scroll_x": 0,
  "scroll_y": 600,
  "delta_x": 0,
  "delta_y": 600,
  "page_events": [],
  "event_scope": "scroll_call_interval"
}
```

`amount`는 요청값, `scroll_x/y`는 대기 후 관측한 절대 좌표, `delta_x/y`는 시도 직전부터 관측까지의 실제 좌표 차이다. 이 구간의 사이트 반응·스크롤 스냅·레이아웃 변화가 포함될 수 있으므로 요청만의 인과적 이동량이라고 단정하지 않는다.

| 상황 | status | attempted | moved | 좌표·이동량 |
|---|---|---|---|---|
| 실제 좌표 변화 확인 | success | true | true | 관측값 |
| 시도했으나 변화 없음 | success | true | false | 관측값, delta 0 |
| 한도·관측 검사에서 거절 | failed | false | false | null |
| 시도 후 timeout·페이지 이동·종료로 확인 불가 | timeout 또는 failed | true | null | null |

페이지 끝에서 600px을 요청하고 0px이 관측돼도 동작·좌표 확인은 성공일 수 있다. `moved:false`만으로 페이지 전체 조사 완료나 그 원인을 판단하지 않는다. `attempted:true`는 브라우저 명령을 시도한 경계이며 확실한 입력 수신의 보증은 아니다. 시도 후 오류가 나도 예약을 돌려주거나 자동 재시도하지 않는다. 외부 작업 취소는 취소로 전파하고 임시 참조·이벤트 구간을 정리한다.

공통 반환에는 시작·종료 시각, 오류, `before_state_id`가 들어간다. 자동 재관측을 하지 않으므로 `after_state_id`는 null이고 `observer_refs`는 빈 목록이다. 실제 이동 후 화면 내용이 필요하면 호출 Agent가 관측 Tool을 선택한다.

상태 무효화는 마지막으로 읽은 정보를 최신 상태로 재사용하지 못하게 하는 처리다. 탭·세션·이동 위치는 유지된다. `get_page_state`에 `context.state_id=null`로 요청하면 조회 안에서 새 관측을 얻는다. 다음 행동에 쓸 요소는 `params.include=["elements"]`로 함께 받는다. 별도 refresh Tool이나 브라우저 새로고침이 필요 없다. SDK 실행 Agent는 작업에서 허용된 조회를 이어 호출한다.

## SDK 실행부 연결

```python
scroll = ScrollTool(
    page_state,
    timeout_ms=settings.scroll_timeout_ms,
    wait_ms=settings.scroll_observation_wait_ms,
    page_events=page_events,
    reserve_attempt=reserve_scroll_attempt,
)
native_tools["scroll"] = scroll  # register_native_tools에 전달
```

`settings`, `reserve_scroll_attempt`, `native_tools`는 호출측 연결을 보여주는 이름이다. 새 운영 설정·전역 횟수 관리자를 이번 Tool에서 만들지 않았다. `timeout_ms`는 양의 정수, `wait_ms`는 0 이상이고 timeout보다 작은 정수로 호출측이 제공한다. 횟수 차감은 조사 전체를 소유한 호출측 책임이며 Tool 인스턴스를 다시 만들어도 같은 예약 함수를 연결할 수 있다. SDK의 공통 실행 한도와 이 스크롤 횟수 한도는 별개다.

PageState와 PageEvents는 같은 인스턴스를 공유해야 한다. 같은 Page의 행동·관측은 실행 환경이 순차로 수행한다. 페이지 이동·새 탭 알림은 기존 PageEvents가 전달하며 Tool 결과에는 호출 구간의 사건만 남긴다. 반환 뒤 늦게 발생한 사건은 지속 연결을 통해 전달되고 이전 action_id로 자동 귀속하지 않는다.

별도 파일·스크린샷·AWS 저장을 추가하지 않는다. SDK 연결이 입력과 실제 결과를 Store에 기록하고 작업 결과 전달은 `review_after`를 따른다.

## 검증 범위

`tests/test_scroll.py`는 통제된 로컬 페이지와 실제 Edge를 사용한다. 네 방향, 내부 상자 위의 마우스와 문서 대상 구분, DOM 변화 없는 상태 무효화, 일부·0 이동, 공유 횟수 한도, 입력 거절, 지연 DOM 변화, CSS 스냅, 다른 URL·같은 URL 재로딩·같은 문서 이동, 실제 이동 뒤 timeout·취소, 페이지 종료, 예약 함수 실패, 기존 flow의 실제 입력·반환 전달을 확인한다.

최종 코드의 표적 검사 **25 passed (28.03s)**, 기존 검사를 포함한 전체 **150 passed (167.20s)**. 독립 검토자는 동일 고정본의 문서 대상·경계·공유 한도·스냅·세 종류의 이동·timeout/cancel 정리 표적 검사 **8 passed (13.68s)**를 확인했다. 실제 실행 Agent·총괄 LLM·외부 의심 사이트·AWS 진행 API는 이번 검증 범위에 포함하지 않는다.
