# click — 조회한 요소를 같은 브라우저에서 클릭

현재 SDK 연결은 [AGENTS_SDK.md](AGENTS_SDK.md)를 따른다. 아래 날짜가 붙은 초기 검증 기록은 당시 범위이며, 현재 실행 검사 결과는 [정리 검증 기록](../output/l4-sdk-cleanup-20261002/)에서 확인한다.

사용자가 승인한 단일 click Tool을 구현했다. 기존 요소 조회에서 받은 `element_id`로 **그때 본 실제 노드**를 클릭한다. 같은 Page·PageState·ElementRegistry를 이어서 사용한다.

## 우리 흐름에서 쓰는 순서

1. Agent가 `get_page_state(params.include=["elements"], context.state_id=null)`로 버튼·링크 등의 ID와 새 관측 ID를 받는다. 조회 안에서 현재 페이지를 수집한다.
2. Agent가 선택한 요소 ID와 반환된 관측 ID로 `click`을 호출한다.
3. Tool은 현재 관측과 요소를 확인하고 일반 왼쪽 클릭을 한 번 요청한다.
4. 클릭 시도 직전에 기존 PageState를 무효화한다. 다음 판단에 새 상태가 필요하면 조회 Tool에 `state_id=null`로 요청한다.

Tool은 상태 갱신·스크린샷·파일 저장을 자동으로 추가하지 않는다. SDK 연결이 입력과 실제 반환을 Store에 기록한다.

## 입력과 반환의 의미

```json
{
  "action_id": "click-1",
  "tool": "click",
  "target": {"element_id": "요소 조회에서 받은 ID"},
  "params": {},
  "context": {
    "job_id": "job-1",
    "scenario_id": "investigation-1",
    "step_id": "press-button",
    "state_id": "해당 요소를 조회한 상태 ID"
  }
}
```

`state_id=null`이면 현재 유효한 관측과 최신 성공한 요소 목록을 사용한다. 새 상태를 자동 수집한다는 뜻은 아니다. `force`나 선택자 같은 추가 입력은 받지 않는다.

반환값에는 공통 실행 상태·시각·오류, `element_id`, `clicked`, `page_events`가 있다.

| `clicked` | 의미 |
|---|---|
| `true` | Playwright의 클릭 호출이 정상 완료됐다. 로그인 성공·내용 확인 완료 등을 뜻하지 않는다. |
| `false` | 클릭 호출에 들어가기 전에 거절·실패했다. 예: 숨겨진 버튼, 비활성 버튼, 잘못된 ID. |
| `null` | 클릭 호출을 시도했지만 완료 여부를 확인하지 못했다. 입력 전달 후 이동을 기다리다가 시간 초과가 날 수도 있다. |

`null`을 클릭 미실행으로 해석해 자동 재시도하면 안 된다. 먼저 현재 페이지를 확인해야 한다. 외부에서 작업을 취소한 경우에도 이미 전달된 입력이나 진행 중인 이동을 되돌렸다고 간주하지 않는다. 중단 후 브라우저 정리는 실행 환경의 책임이다.

`before_state_id`는 실제 확인한 관측 ID다. `after_state_id=null`은 이 Tool이 클릭 후 관측을 생성하지 않았다는 뜻이다. `observer_refs`는 L2/L3 관측기 연결 전이므로 빈 목록이다.

현재 상태에 없는 ID는 `ELEMENT_NOT_FOUND`, 오래되거나 변경된 관측은 `TARGET_STALE`, 숨김은 `ELEMENT_NOT_VISIBLE`, 비활성·inert는 `ELEMENT_DISABLED`, 시간 초과는 `ACTION_TIMEOUT`으로 반환한다. 닫힌 페이지와 브라우저 충돌도 별도로 구분한다.

노드가 제거되면 같은 선택자나 이름의 다른 노드를 대신 클릭하지 않는다. Playwright는 정상 클릭 내부에서 준비 상태·가림 여부를 기다리고 필요하면 스크롤한다. **우리 Tool의 클릭 호출은 한 번이며**, Playwright 내부의 준비 상태 확인까지 한 번만 한다는 뜻은 아니다. 관측 확인과 입력 사이에 웹페이지 전체를 동결하는 것은 아니다.

## 이동과 새 탭을 놓치지 않는 연결

실제 브라우저에서는 새 탭 알림이 클릭 반환보다 늦게 도착할 수 있다. 따라서 실행 환경이 `PageEvents`를 같은 Page에 한 번 연결해 유지한다. 이것은 이동·새 탭 알림을 전달하는 작은 연결부다. 탭 목록 관리, 조사 대상 전환, 새 탭 닫기나 관측 갱신은 하지 않는다.

```python
from l4_orchestrator.page_events import PageEvents
from l4_orchestrator.tools.click import ClickTool

# state와 elements는 앞에서 쓰던 동일 PageState와 ElementRegistry.
# runtime_receive_page_event는 실행 환경이 제공하는 동기 알림 함수다.
# 인자로 (event 메타데이터, 실제 Page 객체)를 받고, 후속 작업을 큐 등에 넘긴다.
page_events = PageEvents(state, on_event=runtime_receive_page_event)
click = ClickTool(elements, timeout_ms=action_timeout_ms, page_events=page_events)
native_tools["click"] = click  # register_native_tools에 전달

# 실행 환경이 해당 Page 사용을 마칠 때 해제한다. 클릭마다 해제하지 않는다.
# page_events.close()
```

- **실행 환경 콜백:** 원래 Page가 살아 있는 동안 현재 페이지 이동과 새 탭을 받는다. 새 탭의 실제 Page 객체도 받아 이어서 관리할 수 있다. 원래 Page가 닫히면 연결은 자동 해제된다. opener가 닫힌 뒤 발생하는 새 페이지까지 다루려면 실행 환경의 BrowserContext 처리가 별도로 필요하다.
- **click 반환의 `page_events`:** 클릭 시도 구간에 관측된 사건만 포함한다. 이후 사건이 도착해도 이미 반환한 결과를 바꾸지 않는다. 빈 목록은 새 탭이 나중에도 없다는 보장이 아니다. `event_scope`는 `click_call_interval`이다.
- **사건 메타데이터:** 종류, 원래 `source_page_id`, 사건 당시 URL·관측 시각, `observed_during_action_id`를 제공한다. 새 탭 URL은 아직 최종 주소가 아닐 수 있다. 행동 ID는 해당 호출 구간에 관측됐다는 뜻이며 인과관계 증명이 아니다. 구간 밖이면 `null`로 두고 마지막 클릭에 억지로 연결하지 않는다.
- **알림 전달 실패:** 클릭을 다시 실행하거나 성공을 실패로 바꾸지 않는다. 해당 사건에 `delivery_error`를 남기고 `PageEvents.last_delivery_error`에 최근 전달 실패 하나를 유지한다. 늦은 알림의 실패도 실행 환경이 확인할 수 있다. 콜백은 긴 작업을 직접 수행하지 않고 후속 처리를 넘기는 동기 함수여야 한다.

같은 Page의 행동·갱신은 실행 환경이 순차로 호출한다. 클릭으로 생기는 네트워크 요청·다운로드·팝업 정책과 전체 브라우저 세션은 기존대로 실행 환경이 담당한다.

## 파일과 확인 범위

- [tools/click.py](src/l4_orchestrator/tools/click.py): 입력 검사, 실제 클릭, 상태 무효화, 결과 반환, 공통 ExecutionPort 제공.
- [page_events.py](src/l4_orchestrator/page_events.py): Page 수명 동안 이동·새 탭을 실행 환경에 전달.
- [elements.py](src/l4_orchestrator/elements.py): 기존 실제 노드 조회를 재사용. 현재 목록에 없는 ID와 오래된 관측의 오류를 구분하도록 작은 수정.
- [test_click.py](tests/test_click.py): 실제 headless Edge와 통제된 로컬 페이지에서 실행.

새 click 검사 15개와 기존 요소 조회 6개가 **21 passed (30.69s)**로 통과했다. 버튼·링크, DOM 변화 없는 클릭, 숨김·비활성·가림, 교체된 노드, 클릭 뒤 이동 대기 시간 초과, 늦은 새 탭, 콜백 오류, 기존 flow로 결과 전달을 확인했다. 실제 Agent가 판단해 Tool을 선택하는 과정, 외부 의심 사이트, AWS 진행 API는 이 검사의 범위가 아니다.

2026-09-28 최종 전체 검사 **80 passed (59.47s)**. 독립 검토자는 고정된 구현·검사 파일 4개의 해시를 대조하고 핵심 실제 Edge 검사 **5 passed (12.18s)**를 재현했다. 이후 추가한 공통 테스트 초기화 변경도 별도로 확인했다.

첫 전체 실행은 기존 페이지 상태 검사의 최초 refresh에서 `STATE_CHANGED`가 발생해 79 passed / 1 failed였다. 공통 브라우저 검사 준비에 첫 렌더링 기회를 기다리는 처리를 추가한 뒤 위 결과를 확인했다. 제품 코드의 상태 검사·무효화는 변경하지 않았고 실패 무시나 자동 재시도도 추가하지 않았다. 첫 렌더링 대기가 웹페이지의 모든 비동기 변화 종료를 보장하는 것은 아니다.

```powershell
$env:L4_BROWSER_CHANNEL = 'msedge'
& './.venv/Scripts/python.exe' -m pytest tests/test_click.py -q -p no:cacheprovider
```
