# press_key — 확인한 입력창에서 Enter 한 번

2026-10-02 사용자가 승인한 첫 범위를 구현했다. 현재 요소 조회에서 확인한 입력창에 포커스를 주고 Enter를 한 번 보낸다. 키 입력 명령의 완료를 반환하며 폼 제출·서버 수신·페이지 이동 성공을 대신 판단하지 않는다.

## 사용 흐름

`fill → get_page_state(params.include=["elements"], context.state_id=null) → press_key → 필요한 페이지·네트워크 조회`

fill은 이전 관측을 무효화한다. 따라서 fill 전의 element_id와 state_id를 그대로 사용하지 않고, 다음 요소 조회에서 받은 실제 ID로 press_key를 호출한다. 제출 버튼을 누르는 경우에는 기존 click을 사용한다. 이 Tool은 입력창에서 Enter 동작이 필요한 경우에 쓴다.

```python
from l4_orchestrator.tools.press_key import PressKeyTool

tool = PressKeyTool(
    elements,  # 기존 ElementRegistry
    timeout_ms=key_input_timeout_ms,
    page_events=page_events,  # elements와 같은 PageState에 연결된 PageEvents
)
reply = await tool.execute({
    "action_id": action_id,
    "tool": "press_key",
    "target": {"element_id": observed_element_id},
    "params": {"key": "Enter"},
    "context": {
        "job_id": job_id, "scenario_id": scenario_id,
        "step_id": step_id, "state_id": observed_state_id,
    },
})
```

한도는 호출측이 양의 정수로 제공한다. 같은 PageState·ElementRegistry·PageEvents를 다른 브라우저 Tool과 공유하고 한 Page의 행동은 순서대로 호출한다. `native_tools["press_key"] = tool`로 기존 객체를 SDK의 `register_native_tools`에 전달한다. SDK 실행부가 Tool 허용 범위·ACT·Store 기록을 연결한다.

## 입력 범위와 내부 동작

첫 범위는 **key="Enter" 한 번**이다. 키 조합·다른 키·반복 횟수·입력 문자열을 받지 않는다. 대상은 기존 fill과 같은 native input의 text/search/email/password/tel/url 또는 textarea다. 숨김·비활성·inert·readonly 입력창과 사용자 정의 편집기는 거절한다. iframe·shadow 내부를 새로 탐색하거나 임의 selector로 대상을 다시 찾지 않는다.

1. 요청 형식과 현재 관측을 확인한다. context.state_id가 null이면 이미 유효한 현재 관측을 사용하며 새 관측을 만들지 않는다.
2. ElementRegistry에서 조회 때의 원래 노드를 찾아 연결 상태·종류·표시·활성·쓰기 가능 여부를 확인한다.
3. PageEvents의 호출 구간을 시작하고, 포커스를 주기 전에 이전 관측을 무효화한다.
4. 원래 노드에 포커스를 준 뒤 같은 노드가 여전히 사용 가능하고 포커스를 유지하는지 다시 확인한다. 포커스 처리로 다른 입력창으로 이동하거나 원래 노드가 교체되면 키를 보내지 않는다.
5. 기존 Page의 keyboard.press("Enter")를 한 번 호출한다. 완료되면 pressed=true를 반환한다. 다음 동작이나 자동 재시도는 수행하지 않는다.

키 동작은 페이지가 결정한다. Enter를 막는 페이지에서는 제출되지 않을 수 있고, textarea에서는 줄바꿈이 들어갈 수 있다. 이 경우에도 브라우저의 키 입력 명령이 정상 완료됐다면 pressed=true다. 입력값 자체를 읽거나 변경 전후의 값으로 성공을 추정하지 않는다.

## 반환을 읽는 방법

기존 Browser Tool의 action_id·tool·status·시각·상태 ID·observer_refs·error 형식을 사용한다. result에는 element_id, key, pressed, page_events, event_scope가 있다.

| 항목 | 뜻 |
|---|---|
| pressed=true | Enter 키 입력 명령이 정상 완료됨. 제출·서버 수신 성공의 확인은 아님. |
| pressed=false | 키 입력 명령을 시작하지 않음. 포커스 처리까지 시도했다면 그 과정의 화면 변화는 있을 수 있음. |
| pressed=null | 키 입력 명령을 시작했으나 완료를 확인하지 못함. 실제 키 입력이 이미 발생했을 수 있으므로 바로 반복하지 않고 먼저 관측함. |
| before_state_id | 대상을 확인한 관측 ID. 관측 확인 전 실패하면 null. |
| after_state_id | null. 이 Tool은 행동 후 새 관측을 만들지 않음. |
| page_events | 호출 구간에서 받은 현재 페이지 이동·새 Page 알림. |
| event_scope | press_key_call_interval. 호출 뒤 발생한 모든 사건을 포함한다는 뜻은 아님. |

호출 뒤 늦게 도착한 알림도 기존 PageEvents가 살아 있는 동안 호출측으로 전달한다. 늦은 사건을 끝난 action_id에 임의로 연결하지 않으며 새 탭으로 조사 대상을 자동 전환하지 않는다. 콜백 전달 실패는 기존 PageEvents의 delivery_error로 구분한다.

입력 형식이 틀리면 브라우저 접근 전에 ValidationError로 거절한다. 주요 실행 오류는 TARGET_STALE, ELEMENT_NOT_FOUND, ELEMENT_NOT_VISIBLE, ELEMENT_DISABLED, BLOCKED_ACTION, PAGE_CLOSED, BROWSER_CRASH, ACTION_TIMEOUT, INTERNAL_ERROR다. 시간 초과의 status는 timeout, 나머지 실행 실패는 failed다. Page 종료·충돌은 recoverable=false다.

취소는 CancelledError로 전달한다. 호출 구간의 알림 연결과 임시 노드 핸들을 정리하고 자동 재입력하지 않는다. 시간 초과·취소가 이미 보낸 키나 그 결과를 되돌린다는 뜻은 아니다. 취소 뒤에도 다음 행동 전에 새 관측이 필요하다.

## 저장과 담당 범위

별도 파일 저장·Store 호출·AWS 전송을 추가하지 않는다. 짧은 Tool 반환과 action_id는 실행부가 기존 방식으로 기록할 수 있다. 실제 서버 수신이나 화면 변화의 근거가 필요하면 기존 네트워크·페이지 조회를 사용한다. 총괄에게 무엇을 보고할지는 실행 Agent와 총괄의 책임이다.

## 확인한 범위

신규 검사 **16 passed (22.86s)**. Windows headless Edge와 통제된 로컬 HTTP를 사용했다. 실제 fill → 과거 관측 거절 → 요소 재조회 → Enter → POST 1회 → 페이지 본문 재조회 → 기존 flow의 다음 시험용 총괄 입력을 확인했다. 같은 Page·쿠키 유지, 제출이 막힌 경우와 textarea 줄바꿈, 부적합 대상·포커스 이동·원래 노드 제거, 실제 키 입력 뒤 시간 초과·취소·응답 오류에서 자동 재입력이 없는지도 확인했다. 시간 초과·취소·응답 오류 일부는 실제 키 입력 뒤 응답 지연/오류를 주입했다.

기존 PageState·요소 조회·관측 갱신·click·fill·flow 회귀 **96 passed (144.99s)**를 확인했다. 공통 서비스 코드와 기존 Tool 구현은 변경하지 않았다. 실제 모델의 조사 판단, 새 SDK 등록·운영 연결, AWS·사용자 화면, Linux 브라우저에서의 이 Tool 실행은 이 로컬 검사로 확인하지 않는다. export_page 검증 때 한 차례 실패한 기존 Bash 취소 검사의 원인은 이번 작업에서 다루지 않았다.

## 독립 검토와 실제 입력·출력

독립 검토자가 같은 고정 소스의 핵심 **8 passed (17.20s)**를 확인했고 검토한 범위에서 수정 필수 결함을 발견하지 못했다. 서비스·공식 검사 파일을 변경하지 않았다. [검사 결과 XML](.test-tmp/press-key-review-762c801ae24240d493dc0cb1b4ab3a5e/results.xml)과 [원 HTML·입력·서버 수신·Tool 반환·후속 총괄 입력](.test-tmp/press-key-review-762c801ae24240d493dc0cb1b4ab3a5e/core-1/test_fill_refresh_enter_post_a0/flow-evidence.json)을 보존했다. 이 JSON은 시험 산출물이며 Tool이 매 호출마다 저장하는 파일이 아니다.

구현 측도 이 독립 실행 원문을 직접 열어 다음을 대조했다.

- 제출 버튼 없는 이메일 폼에서 fill(dummy_email) 후 과거 관측으로 Enter를 요청하면 TARGET_STALE·pressed=false였다.
- 새 요소 조회 후 Enter를 보내자 로컬 서버가 POST /submit을 한 번 받았다. 본문은 email=l4-test%40example.com, 쿠키는 enter_session=kept였고 같은 Page를 유지했다.
- press_key의 실제 요청·반환과 다음 고정 총괄 입력이 일치했다. 별도 get_page_content에서 “서버가 입력을 받았습니다.”를 읽었으며 그 결과도 후속 입력과 일치했다.
- 이 실행에서 Enter 반환의 page_events는 빈 목록이었다. 이동은 반환 뒤 확인됐다. **빈 호출 구간 이벤트 목록은 이후 이동이 없었다는 근거가 아니다.** 시험 연결부는 알려진 로컬 응답의 로드 완료를 기다린 뒤 본문을 조회했다. Tool 자체에 이 대기나 페이지 결과 판단을 넣지 않았다.
- 제출 방지·textarea 줄바꿈, 포커스 이동·대상 교체, 실제 Enter 뒤 응답 지연·오류·취소를 별도로 확인했다. 키 입력이 이미 일어났을 수 있는 경우에는 재입력하지 않았다.

검토 전후 두 파일의 SHA-256이 같았다. 이후 작업은 설명 문서 정리뿐이다.

| 파일 | SHA-256 |
|---|---|
| src/l4_orchestrator/tools/press_key.py | 4696CAC35BF158AA2D454823688226B49225A4394FEADA86DE9C1F9CFB15EC7E |
| tests/test_press_key.py | 7015927AF8D1E6E0CCA2CEE100DE4BE33D93096FE0E227252F854F67BB5A4B93 |

검사 실행 환경 참고: 신규 16개 실행 후 기본 실행 계정에서 프로세스 시작 오류 1909가 발생해, 기존 회귀·독립 검토는 일반 실행 환경에서 수행했다. 최초 검사 폴더의 추가 읽기는 접근 거절되어, 원문 대조에는 같은 고정 코드로 다시 생성한 위 독립 실행 자료를 사용했다. 이 환경 전환을 코드 결함 수정으로 표시하지 않는다.
