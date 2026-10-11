# reload — 같은 탭의 페이지 새로고침

현재 SDK 연결은 [AGENTS_SDK.md](AGENTS_SDK.md)를 따른다. 아래 날짜가 붙은 초기 검증 기록은 당시 범위이며, 현재 실행 검사 결과는 [정리 검증 기록](../output/l4-sdk-cleanup-20261002/)에서 확인한다.

2026-09-28 승인 범위 구현·로컬 회귀·독립 검토 완료. 구현은 `src/l4_orchestrator/tools/reload.py`의 `ReloadTool`이다. 실제 실행 Agent·AWS 연동은 별도 단계다.

## 실제 조사에서의 역할

`현재 화면 관측 → Agent가 새로고침 결정 → reload → 새 화면 관측 → Agent가 변화 해석`

`PageState.refresh()`는 현재 열린 페이지의 정보를 다시 읽는다. `reload`는 브라우저 새로고침처럼 웹페이지 자체를 다시 불러온다. 같은 Page와 브라우저 context를 유지하며, 페이지 내용·입력 상태·사이트 자체의 반응은 새로고침으로 달라질 수 있다. 쿠키나 저장소를 Tool이 초기화하지는 않는다.

Tool은 새로고침 실행과 완료 여부를 반환한다. 내용이 바뀌었다는 사실이나 클로킹·악성 여부를 자동 판단하지 않는다. [확정 reload 명세](https://l4-browser-tool-spec-light-pages.vercel.app/#/reload)의 Observer·State Diff는 우리 구조에서 호출측의 후속 관측·비교로 연결한다. 이번 Tool 안에 자동 수집·비교 기능을 추가하지 않는다.

## 입력

```json
{
  "action_id": "reload-1",
  "tool": "reload",
  "target": null,
  "params": {"wait_until": "domcontentloaded"},
  "context": {
    "job_id": "현재 조사 ID",
    "scenario_id": "현재 시나리오 ID",
    "step_id": "새로고침 뒤 관측 단계 ID",
    "state_id": "현재 관측 ID"
  }
}
```

현재 탭을 새로고침하므로 목적지 URL이나 요소 ID를 받지 않는다. `state_id`는 동작을 결정할 때 사용한 관측과 현재 관측이 일치하는지 확인한다. null은 현재 유효한 관측을 사용한다는 뜻이며, 관측 없이 실행한다는 뜻은 아니다.

`wait_until`은 기본 `domcontentloaded`이며 `commit`, `load`, `networkidle`도 기존 navigate·go_back과 같이 받는다. 기본값은 문서의 DOMContentLoaded까지 기다리는 것이며, 동적 내용 전체가 표시될 때까지 기다린다는 뜻은 아니다. 호출측은 양의 정수 `timeout_ms`를 Tool 생성 시 제공한다. [Playwright reload 설명](https://playwright.dev/python/docs/api/class-page#page-reload).

## 동작과 반환

1. 현재 관측과 PageEvents 연결을 확인한다.
2. 기존 PageState를 무효화한다. URL·HTML이 같아도 새 문서의 요소를 예전 노드로 취급하면 안 된다.
3. 같은 Page에 `page.reload()`를 한 번 호출한다.
4. 완료 여부·현재 주소·HTTP 상태와 호출 중 페이지 사건을 반환한다. 임시 사건 수집 구간을 정리하고, Page와 지속적인 PageEvents 연결은 유지한다.

공통 반환의 `result`에는 `url`, `reloaded`, `http_status`, `page_events`, `event_scope: "reload_call_interval"`가 들어간다.

| reloaded | 의미 |
|---|---|
| true | 요청한 wait_until까지 새로고침 동작이 완료됨 |
| false | 오래된 관측·닫힌 페이지 등으로 시도 전에 거절됨 |
| null | 시도했지만 시간 초과·실패로 완료 여부를 확인하지 못함 |

`url`은 반환 시 확인한 주소다. 리다이렉트가 발생했다면 실제 도착 주소를 반환한다. 페이지가 닫혔으면 null이다. 시간 초과일 때는 주소만으로 새로고침 완료를 판단하지 않는다. HTTP 404도 문서 로딩이 완료될 수 있으므로 동작 성공과 HTTP 상태를 구분한다. HTTP 응답이 없는 페이지에서는 http_status가 null일 수 있다.

시도 후에는 이전 관측을 다시 살리지 않는다. reload가 자동 재관측하지 않으므로 공통 `after_state_id`는 null이다. 이후 `get_page_state(params.include=["elements"], context.state_id=null)`로 새 관측과 요소 목록을 얻어 다음 행동을 이어간다. 주소와 HTML이 그대로여도 재조회에서 발급된 요소 ID를 사용한다.

시간 초과는 브라우저에서 새로고침이 취소됐다는 뜻이 아니다. 늦게 완료될 수 있으므로 자동 재시도하지 않는다. 외부 취소는 취소로 전파하고 임시 사건 수집 구간을 정리한다. 반환 후 사건은 기존 PageEvents를 통해 실행 환경에 전달하며 과거 action_id로 자동 귀속하지 않는다. 사건 목록은 호출 구간의 관측이며, 모든 사건의 원인이 이 Tool이라고 단정하지 않는다.

이동 중단 오류가 탭 종료 알림보다 먼저 도착할 수 있다. 이때 남은 제한 시간 안에서 페이지가 살아 있는지 읽기 전용으로 한 번 확인하고, 실제 관측된 닫힘·크래시 상태로 오류를 구분한다. 요청 중단 자체를 탭 종료로 단정하지 않는다. 별도 DOM 증거나 새 PageState를 수집하는 과정은 아니다.

## 연결과 저장

```python
reload_tool = ReloadTool(
    page_state,
    timeout_ms=settings.navigation_timeout_ms,
    page_events=page_events,
)
native_tools["reload"] = reload_tool  # register_native_tools에 전달
```

같은 PageState에 연결한 PageEvents를 제공한다. 실행 환경이 동작·관측·요소 조회를 순차 실행하고 네트워크 접근 정책을 적용한다. 별도 파일·스크린샷·AWS 저장을 추가하지 않는다. SDK 연결이 입력·결과를 Store에 보관하고 작업 결과 전달은 `review_after`를 따른다.

## 검증 범위

실제 Edge와 외부 접속이 차단된 로컬 페이지로 같은 탭·세션 유지, DOM 변화와 동일 HTML의 새 문서, 오래된 요소 거절, redirect·404·HTTP 응답 없음, 시간 초과·지연 완료·취소·페이지 종료, 입력 검사 및 실제 결과의 flow 전달을 확인했다. 새 검사 **22 passed (38.66s)**, 기존 검사를 포함한 전체 **216 passed (377.29s)**다.

독립 검토자는 동일 고정본의 핵심 실제 Edge 검사 **9 passed (24.97s)**를 확인했다. 실제 요청 중단 뒤 생존 조회에 오류·무한 대기·취소를 주입한 3개 추가 반례에서도 성공 오표시·시간 제한 초과 대기·사건 구간 정리 누락이 없음을 확인했다. 500ms 제한의 지연 반례는 약 511ms에 반환했으며, 시간 제한이 정확한 실시간 스케줄링을 보장한다는 뜻은 아니다. 종료 오류 분류는 반환 시점까지 관측한 close/crash에 한정한다.

최종 SHA256은 구현 `8F855707D1363577E88099F14C9175623D09DE21197D363A63B05015152A484A`, 검사 `F48180EFC096D650130903CFD8B92E0A1BF8B3AA9B57E23CC3EF22DA80EA0127`다. 실제 모델의 Tool 선택, 외부 사이트 조사, AWS 진행 API와 자동 비교 기능은 이번 범위에 포함하지 않는다.
