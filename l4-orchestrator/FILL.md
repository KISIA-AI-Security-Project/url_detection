# fill — 기존 입력칸에 분석용 값 입력

현재 SDK 연결은 [AGENTS_SDK.md](AGENTS_SDK.md)를 따른다. 아래 날짜가 붙은 초기 검증 기록은 당시 범위이며, 현재 실행 검사 결과는 [정리 검증 기록](../output/l4-sdk-cleanup-20261002/)에서 확인한다.

사용자가 승인한 단일 fill Tool을 구현했다. 같은 Page와 요소 조회 결과를 이어서 사용하며, 입력칸에 다섯 가지 고정된 분석용 값 중 하나를 넣는다.

## 우리 흐름에서 쓰는 방법

1. Agent가 `get_page_state(params.include=["elements"], context.state_id=null)`로 현재 페이지의 입력칸 ID와 새 관측 ID를 얻는다.
2. Agent는 입력칸 ID, 분석용 값의 종류, 기존 내용을 지울지를 지정한다.
3. fill은 실제 노드와 관측 상태·입력 가능 여부를 확인한 후 입력한다.
4. 실제 입력이 선택한 노드에서 발생했고, 직후 값이 요청한 교체·추가 결과와 맞는지 브라우저 안에서 확인하고 결과를 반환한다.
5. 다음 행동에 새 관측이 필요하면 조회 Tool에 `state_id=null`을 전달한다. 제출 버튼을 누를지는 호출 Agent가 별도로 결정한다.

## 입력

공통 `action_id`, `tool`, `context`와 아래 항목을 사용한다. `context.state_id`가 null이면 현재 유효한 관측과 최신 성공한 요소 조회를 기준으로 검사한다. 자동 관측을 뜻하지 않는다.

```json
{
  "action_id": "fill-1",
  "tool": "fill",
  "target": {"element_id": "요소 조회에서 받은 ID"},
  "params": {"value_type": "dummy_email", "clear_first": true},
  "context": {
    "job_id": "job-1",
    "scenario_id": "investigation-1",
    "step_id": "enter-test-value",
    "state_id": "관측 상태 ID"
  }
}
```

| 항목 | 의미 |
|---|---|
| `value_type` | `dummy_username`, `dummy_email`, `dummy_password`, `dummy_phone`, `dummy_text` 중 하나. |
| `clear_first=true` | 기존 내용을 분석용 값으로 교체한다. 생략 시 기본값이다. |
| `clear_first=false` | 기존 내용 끝에 분석용 값을 추가한다. 현재 커서 위치에 끼워 넣는 의미가 아니다. |

문자열을 직접 받는 `value` 필드는 없다. 허용하지 않는 종류·필드·문자열 형태의 불리언은 입력 전에 거절한다. 고정 preset은 Tool 코드에 있고 Agent가 값을 생성하거나 전달하지 않는다. 계정 생성·문자 수신·로그인 성공을 위한 실제 개인정보가 아니다.

지원 대상은 native `input`의 text/search/email/password/tel/url과 `textarea`다. 읽기 전용·비활성·숨김·교체된 요소를 거절한다. contenteditable, 숫자·날짜·파일·체크박스 등은 이번 범위에서 지원하지 않는다. label을 통해 다른 입력칸으로 대상을 바꾸지 않는다.

## 실제 입력과 성공 확인

기존 ElementRegistry의 실제 노드를 사용한다. 사전 확인 뒤 입력을 시도하기 직전에 이전 PageState를 무효화한다. 실제 입력은 Playwright의 `fill()` 또는 키보드 입력을 사용한다. HTML 값을 직접 바꾸고 합성 input 이벤트로 대체하지 않는다.

교체는 같은 노드의 `fill()`을 사용한다. 추가는 포커스를 확인하고 `ControlOrMeta+End`로 끝으로 이동한 뒤 `insert_text()`로 입력한다. 여러 줄 textarea에서도 마지막 줄의 끝을 대상으로 한다. email은 선택 위치를 읽는 DOM API를 지원하지 않으므로, 해당 API에 의존하지 않고 입력 후 결과를 확인한다. 이 경로는 실제 Edge에서 검사했다.

길이 제한을 넘는 요청은 입력 전에 거절한다. 포커스나 끝 이동 키의 처리로 다른 칸이 활성화되면 텍스트를 보내지 않는다. 기존 값과 예상 결과는 브라우저 안의 임시 참조로만 다루며, **입력 직후 같은 노드의 값과 일치하는지 여부만 Python으로 가져온다.** 임시 참조는 호출 종료 시 해제한다. 기존 값 전체를 Python으로 읽어 합친 뒤 재입력하지 않는다.

값 비교만으로는 원래 값이 이미 같은 경우를 구분할 수 없다. 입력 구간에 임시 감시를 두어 브라우저가 생성한 실제 input 이벤트의 대상을 확인한다. 선택한 노드에서 입력이 발생하고, 다른 노드에 입력이 발생하지 않았으며, 최종 값도 일치해야 성공이다. 페이지가 직접 만든 합성 input 이벤트는 성공의 증거로 세지 않는다.

`beforeinput`에서 페이지가 입력을 취소하거나 포커스를 다른 칸으로 옮기면, 입력 전에 이를 다시 확인해 취소한다. 페이지가 이벤트 전파까지 차단하면 이 방어를 우회할 수 있고 다른 칸에 입력될 수도 있다. 이 경우에도 다른 노드의 실제 입력이 관측되면 성공으로 표시하지 않고 `filled=null`로 반환한다. 사이트가 일으킨 효과를 자동으로 되돌리지 않는다. 감시·방어 리스너는 호출 종료 시 제거한다. 정리에 필요한 참조를 먼저 확보한 뒤 리스너를 설치하므로 설치 응답 대기 중 취소·시간 초과가 나도 제거할 수 있다.

브라우저 API가 정상 반환했어도 값이 잘렸거나 페이지 스크립트가 즉시 바꿨다면 성공으로 표시하지 않는다. 이 검사는 웹페이지의 모든 동작을 동결하는 기능이 아니다. 비동기 스크립트가 입력 사이에 개입하거나 확인 직후 내용을 바꾸는 것까지 원자적으로 막는다는 보장은 없다.

| `filled` | 의미 |
|---|---|
| `true` | 선택한 노드의 실제 입력과 직후의 값 일치를 확인했다. 이후 값 유지나 로그인 성공은 별개다. |
| `false` | 입력 시도 전 거절·실패했다. |
| `null` | 입력 시도가 시작된 뒤 완료를 확인하지 못했다. 일부 또는 전부가 이미 입력됐을 수 있다. |

오류는 오래된 관측·교체된 노드 `TARGET_STALE`, 등록되지 않은 ID `ELEMENT_NOT_FOUND`, 숨김 `ELEMENT_NOT_VISIBLE`, 비활성 `ELEMENT_DISABLED`, 읽기 전용·미지원·길이 제한·입력 결과 확인 실패 `BLOCKED_ACTION`, 시간 초과 `ACTION_TIMEOUT` 등으로 구분한다. 자동 재입력·Enter·제출·추가 촬영은 수행하지 않는다.

입력 뒤 Enter가 필요하면 요소를 다시 조회해 받은 현재 ID로 [press_key](PRESS_KEY.md)를 호출한다. fill에 자동 제출을 붙이지 않고, 실행 Agent가 입력 결과를 확인한 뒤 다음 행동을 선택한다.

## 반환과 기록

반환에는 공통 실행 상태·시각·오류와 `element_id`, `value_type`, `filled`, 호출 중 관측한 `page_events`가 있다. `before_state_id`는 확인한 관측이고, `after_state_id=null`은 새 관측을 자동 생성하지 않았다는 뜻이다. 별도 파일이나 AWS 기록은 추가하지 않는다. SDK 연결이 Store에 요청한 preset 종류와 결과를 남긴다.

Tool은 입력 문자열을 반환하거나 로그로 출력하지 않는다. Playwright 오류에 입력값이 포함돼도 고정된 오류 설명으로 반환하며, 거절한 입력을 포함하는 Pydantic 오류 문구도 그대로 전달하지 않는다. 입력값이 URL에 복사될 수 있어서 **fill의 사건 반환에서는 URL 전체를 생략**하고 `url=null`, `url_omitted=true`로 표시한다. 사건 종류·페이지 ID·관측 시각과 전달 오류는 유지한다.

이 범위는 fill의 반환·오류·자체 기록이다. 실행 환경에 전달되는 기존 `PageEvents` 실시간 알림은 실제 URL을 유지한다. 다른 관측 Tool의 화면·주소, 외부에서 켠 Playwright 디버그/trace, 총괄 원응답·원요청 이력을 일괄 지우거나 마스킹하는 기능은 추가하지 않았다. 특히 호출자가 잘못 보낸 임의 문자열까지 Store의 원요청에서 삭제한다고 해석하지 않는다.

## 연결과 파일

```python
from l4_orchestrator.tools.fill import FillTool

# click과 동일한 elements, page_events를 재사용한다.
fill = FillTool(elements, timeout_ms=action_timeout_ms, page_events=page_events)
native_tools["fill"] = fill  # register_native_tools에 전달
```

- [tools/fill.py](src/l4_orchestrator/tools/fill.py): 입력 형식·고정 preset·교체/추가 입력·확인·반환·공통 ExecutionPort 제공.
- [tests/test_fill.py](tests/test_fill.py): 실제 headless Edge와 통제된 로컬 페이지에서 기능·실패·SDK 연결 검사.
- [elements.py](src/l4_orchestrator/elements.py), [page_events.py](src/l4_orchestrator/page_events.py), [page_state.py](src/l4_orchestrator/page_state.py): 기존 구현을 변경 없이 재사용.

다섯 preset과 지원 입력 종류, 교체·끝 추가, 길이 제한·포커스 변경·값 재작성, 숨김·비활성·읽기 전용·오래된 대상, 원문 없는 오류·반환과 기존 flow 전달을 확인했다. 독립 검토에서 원래 값이 이미 같은 경우 실제 입력이 다른 칸으로 이동하거나 취소됐는데도 성공으로 반환하는 반례를 발견해 수정하고, 실제 Edge 회귀 검사 3개를 추가했다.

또한 리스너가 설치됐지만 호출측이 아직 참조를 받지 못한 시점에 시간 초과가 나면 이후 다른 입력칸을 방해하는 반례를 수정했다. 실제 Edge에서 설치 응답 지연을 주입한 timeout/cancel 회귀 검사 2개로 확인했다. 이는 자연 발생 통신 지연을 재현했다는 뜻은 아니다. 독립 검토자는 최종 2파일 해시를 대조하고 취소 경계 2개와 기존 값이 같은 경우의 입력 취소 1개, **총 3개**를 최종 상태에서 재검증했다.

2026-09-28 최종 코드로 전체 **125 passed (133.27s)**. 이 중 새 fill 검사는 45개다. 독립 검토 전 120개 통과는 앞의 두 반례 수정을 포함하지 않은 이전 상태이며, 완료 근거는 최종 125개 검사와 수정 후 독립 재검증이다.

```powershell
$env:L4_BROWSER_CHANNEL = 'msedge'
& './.venv/Scripts/python.exe' -m pytest tests/test_fill.py -q -p no:cacheprovider
```

실제 Agent의 Tool 선택·외부 의심 사이트 조사·AWS 진행 API는 이번 검증 범위가 아니다.
