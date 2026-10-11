# go_back — 같은 탭의 방문 기록에서 한 단계 뒤로 이동

현재 SDK 연결은 [AGENTS_SDK.md](AGENTS_SDK.md)를 따른다. 아래 날짜가 붙은 초기 검증 기록은 당시 범위이며, 현재 실행 검사 결과는 [정리 검증 기록](../output/l4-sdk-cleanup-20261002/)에서 확인한다.

2026-09-28 승인 범위 구현·로컬 회귀·독립 검토 완료. `tools/go_back.py`의 `GoBackTool`이 실행 환경에서 받은 같은 Page·PageState·PageEvents를 사용한다. 실제 실행 Agent·AWS 연동은 별도 단계다.

## 조사에서 쓰는 흐름

`목록 A → 상세 B를 열어 조사 → go_back → 현재 화면 관측 → 다음 조사 대상 선택`

목록으로 돌아갈지 결정하는 주체는 호출하는 Agent다. Tool은 브라우저의 방문 기록에서 한 단계 뒤로 가도록 한 번 요청한다. URL을 입력받아 목록을 새로 여는 기능이나 이전 분석 작업을 취소하는 기능이 아니다. 폼 제출·다운로드 등 이미 발생한 일을 되돌리지 않으며, 예전 스크린샷이나 DOM을 복원하지 않는다. 돌아간 주소에서 사이트가 리다이렉트하면 실제 도착한 주소를 반환한다.

## 입력

```json
{
  "action_id": "back-1",
  "tool": "go_back",
  "target": null,
  "params": {"wait_until": "domcontentloaded"},
  "context": {
    "job_id": "현재 조사 ID",
    "scenario_id": "현재 시나리오 ID",
    "step_id": "목록으로 복귀하는 단계 ID",
    "state_id": "현재 관측 ID"
  }
}
```

목적지는 브라우저 방문 기록으로 정해지므로 target은 null이다. `steps: 2`나 임의 URL은 받지 않는다. `state_id`는 이 동작을 결정할 때 사용한 현재 관측을 확인한다. null이면 가장 최근의 유효한 관측을 사용한다. 관측이 아직 없거나 앞선 동작으로 무효화됐다면 먼저 `get_page_state(state_id=null)` 등 조회 Tool로 현재 상태를 확인한다. go_back 자체는 새 관측을 수집하지 않는다.

`wait_until`은 이동을 어느 지점까지 기다릴지 정한다. 기본은 `domcontentloaded`이고 `commit`, `load`, `networkidle`도 기존 navigate와 같이 받는다. 이것이 동적 콘텐츠 전체의 표시나 조사 완료를 보장하지는 않는다. 제한 시간은 Tool 생성 시 실행 환경이 제공한다.

## 내부 처리와 구분 근거

1. 현재 관측과 같은 Page의 사건 전달 연결을 확인한다.
2. Chromium의 실제 방문 기록에서 현재 위치를 읽는다. 확인 시점에 이전 항목이 없다면 뒤로가기를 실행하지 않고 `no_effect`를 반환한다. 앞으로 갈 항목만 남아 있는 경우도 구분한다.
3. 이전 항목이 있으면 기존 PageState를 무효화하고 `page.go_back()`을 한 번 호출한다.
4. 브라우저가 반환한 뒤 방문 기록의 현재 위치가 한 칸 감소했고 현재 항목의 ID가 바뀌었는지 확인한다. URL은 같아도 이동이 가능하다. 같은 문서 내 이동에는 HTTP 응답이 없을 수 있다.
5. 결과를 반환하고 이번 호출의 임시 연결만 정리한다. 원래 Page·세션과 지속적인 PageEvents 연결은 유지한다.

방문 기록 조회는 공개 Playwright CDP 연결의 `Page.getNavigationHistory`를 사용한다. 현재 지원 범위는 Chromium·Chrome·Edge다. 다른 브라우저는 `UNSUPPORTED_BROWSER`로 거절한다. 기록 목록을 별도로 저장하거나 새 방문 기록 관리 계층을 만들지 않는다. [Playwright CDP 지원 범위](https://playwright.dev/python/docs/api/class-browsercontext#browser-context-new-cdp-session), [브라우저 방문 기록 조회 정의](https://chromedevtools.github.io/devtools-protocol/tot/Page/#method-getNavigationHistory).

사이트가 조회와 실제 이동 사이에 `pushState` 등으로 기록을 바꾸면 예상한 한 단계 이동을 확인하지 못할 수 있다. 이 경우 `HISTORY_MOVEMENT_UNCONFIRMED`로 반환한다. 짧은 시간 동안 사건이 없었다거나, URL이 같거나, HTTP 응답이 없다는 이유로 `no_effect`를 만들지 않는다. 브라우저 내부의 과거 페이지 캐시 복원까지 검증한 것은 아니다. [Playwright go_back 동작과 제한](https://playwright.dev/python/docs/api/class-page#page-go-back).

## 결과 읽는 법

목록 A에서 상세 B로 갔다가 돌아온 경우, 공통 반환의 result는 아래와 같다.

```json
{
  "previous_url": "https://분석대상/detail",
  "current_url": "https://분석대상/list",
  "attempted": true,
  "moved": true,
  "http_status": 200,
  "page_events": [],
  "event_scope": "go_back_call_interval"
}
```

위의 page_events는 형식 설명을 위해 생략했다. 실제 이동 사건은 목록에 들어간다. `previous_url`은 뒤로가기 **직전 주소 B**이며 돌아갈 목적지 A를 뜻하지 않는다. `current_url`은 반환할 때 읽은 주소이고, 닫힌 페이지이면 null이다. 특히 timeout·실패에서 current_url만 보고 이동이 완료됐다고 해석하면 안 된다.

| 상태 | attempted / moved | 의미 |
|---|---|---|
| success | true / true | 요청한 대기 지점까지 반환했고 한 단계 뒤의 방문 기록으로 이동한 것을 확인 |
| no_effect | false / false | 확인 시점에 이전 방문 기록이 없어 실제 이동 요청 생략 |
| failed 또는 timeout | false / false | 오래된 관측·닫힌 페이지·기록 조회 시간 초과 등으로 실제 이동을 시작하지 못함 |
| timeout 또는 failed | true / null | 시도했지만 완료와 한 단계 이동을 확정할 수 없음 |

시간 초과 뒤 이동이 늦게 완료될 수 있다. 자동으로 한 번 더 호출하면 두 단계 뒤로 갈 위험이 있어 재시도하지 않는다. 실행 환경이 현재 상태를 관측하고 다음 행동을 결정한다. 외부 취소는 취소로 전달하며 임시 사건 수집 구간과 CDP 연결을 정리한다. CDP 연결 생성 응답 자체가 늦어지면 정리 작업이 소유권을 유지하고, 응답을 받았을 때 연결을 닫는다. 이 정리 작업은 뒤로가기를 실행하지 않는다.

실제 시도를 시작한 뒤에는 예전 PageState를 다시 사용하지 않는다. go_back은 자동 재관측을 하지 않아 `after_state_id`는 null이다. 이후 조회 Tool에 `state_id=null`을 전달하면 새 관측을 얻는다. 이전 기록이 없어 시도 자체를 생략했다면 유효한 기존 관측은 그대로 남는다. 상태와 요소 조회·동작은 동일 Page에서 순차 실행한다.

호출 중 발생한 이동·새 탭 알림은 결과의 page_events에 포함한다. 이후 늦게 발생한 사건은 지속적인 PageEvents를 통해 실행 환경에 전달하며 과거 action_id로 자동 귀속하지 않는다. 이 사건 목록은 호출 구간의 관측이며 모든 사건이 이 Tool 때문에 발생했다는 인과관계를 보장하지 않는다. 탭 선택·전환과 네트워크 접근 정책은 실행 환경의 책임이다.

## 연결과 저장

```python
go_back = GoBackTool(
    page_state,
    timeout_ms=settings.navigation_timeout_ms,
    page_events=page_events,
)
native_tools["go_back"] = go_back  # register_native_tools에 전달
```

직접 `execute(arguments)`로 호출하거나 `native_tools["go_back"] = go_back`로 SDK 등록에 전달한다. Tool이 별도 촬영·파일 저장을 추가하지 않으며, SDK 연결이 입력·반환을 Store에 기록한다. 전체 연결은 [AGENTS_SDK.md](AGENTS_SDK.md)를 따른다.

## 검증

`tests/test_go_back.py`는 실제 Edge와 외부 접속이 차단된 로컬 페이지로 다음을 검사한다.

- 세션·탭 유지, 정확히 한 단계 이동, 네 가지 wait_until, 관측 무효화와 명시적 재관측
- 이전 기록 없음, 앞으로 갈 기록만 있는 첫 항목, 같은 URL의 다른 항목, pushState·해시 이동
- 뒤로가기 중 리다이렉트, HTTP 404 페이지에 실제 도착
- timeout 뒤 늦은 완료, 실제 이동 뒤 응답 지연·취소, 자동 재시도 없음과 연결 정리
- CDP 연결이 실제 생성됐으나 응답만 늦어지는 timeout·취소에서도 늦게 반환된 연결 회수
- 조회와 이동 사이에 기록 변경, 오래된 관측·닫힌 Page, 잘못된 입력·설정
- 같은 실행 입력·실제 브라우저 결과가 기존 flow의 결과 및 다음 총괄 입력까지 전달됨

최종 코드의 표적 검사 **24 passed (30.68s)**, 기존 검사를 포함한 전체 **194 passed (234.30s)**. 독립 검토에서 핵심 9개를 재실행한 뒤 연결 생성 응답 지연 시 정리 누락을 발견했다. 이를 수정하고 최종 고정본에서 관련 timeout·취소 4개를 독립 재검사해 **4 passed (7.10s)**를 확인했다. 자연 발생 지연이 아니라 실제 Edge 연결을 생성한 뒤 반환을 지연시키는 주입 검사로 이 경계를 검증했다.

최종 SHA256은 구현 `97AE6C1E24AF7466F3C23EDB3383CE5DDEABCEBDA31F3DA8C6E4C6119C54EC96`, 검사 `1C93E50000E7382CF379B03A6F52FC671EC3B8EDEC3B0FF04E8E750213AC37BD`다. 늦은 연결 정리는 실행 중인 이벤트 루프에서 이어진다. 이 검증은 실제 모델의 Tool 선택·외부 사이트 조사·AWS 진행 API의 운영 검증을 포함하지 않는다.
