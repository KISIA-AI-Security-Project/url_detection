# 기존 브라우저 Tool에서 탭 지정하기

2026-10-02 사용자 승인 범위: 새 Tool을 추가하지 않고 열린 탭을 찾고 지정하는 기능을 기존 Tool에 붙인다. 이후 승인된 [페이지 조회 통합](PAGE_QUERY.md)으로 현재 native Tool은 총 18개다. `browser_pages.py`는 실행 환경이 사용하는 연결 코드다.

## Agent가 사용하는 순서

기존 `get_page_state`에 `params.scope="pages"`를 주면 같은 BrowserContext에 열린 탭의 `page_id`, URL, 제목을 받는다. 기본 탭이 닫혀 있어도 목록을 조회할 수 있다. 이 호출은 각 탭의 DOM 관측이나 요소 목록을 갱신하지 않으므로 `state_id`를 만들지 않는다.

다음은 SDK에 전달하는 모델 입력이다. `action_id`, `tool`, job/task/action 추적 ID는 기존 SDK 연결이 넣는다.

```json
{"target":null,"params":{"scope":"pages"},"context":{"state_id":null}}
```

목록에서 조사할 탭을 고른 뒤, **반환된 실제 ID**를 이어 사용한다. 아래 `page_...`, `state_...`, `el_...`는 위치를 설명하기 위한 표시다.

```json
{
  "target": null,
  "params": {"include": ["elements"]},
  "context": {"page_id": "page_...", "state_id": null}
}
```

이 입력으로 `get_page_state`를 호출하면 그 탭의 새 관측과 요소 목록을 받는다. 본문도 필요하면 include에 text를 추가한다. 이후 `click`에는 같은 탭의 `page_id`, 방금 반환된 `state_id`, 실제 대상 `element_id`를 넣는다.

```json
{
  "target": {"element_id": "el_..."},
  "params": {},
  "context": {"page_id": "page_...", "state_id": "state_..."}
}
```

`get_page_state`의 기존 `params={}`는 그대로 한 탭의 상태를 관측한다. `page_id`를 생략하거나 null로 주면 처음 연결한 기본 탭을 사용한다. 직전에 다른 탭을 사용했다고 기본 탭이 바뀌지 않는다.

| 값 | 뜻 | 유지 범위 |
|---|---|---|
| `page_id` | 어느 탭인지 | 같은 Page가 이동·새로고침되어도 유지 |
| `state_id` | 그 탭의 어느 관측인지 | 해당 탭의 기존 관측 유효성 규칙을 적용 |
| `element_id` | 그 관측에서 확인한 원래 요소 | 해당 탭의 ElementRegistry가 검증 |

탭 A의 state_id로 탭 B의 요소를 누를 수 없다. B에서 행동해도 A의 관측을 강제로 무효화하지 않는다. 단, 페이지 자체가 다른 탭과 통신해 A를 실제로 바꾸면 A의 기존 변경 감지가 동작한다. 같은 BrowserContext의 쿠키·세션은 계속 공유된다.

## 실행 환경에서 연결하기

`BrowserPages(default_state, create_tools=...)`에 기본 PageState와 **Page마다 기존 Tool을 만드는 함수**를 전달한다. 함수는 받은 state로 ElementRegistry·PageEvents·기존 Tool을 구성하며 같은 Tool 이름 목록을 반환해야 한다. 기본 Page에도 전달한 state 객체를 그대로 사용한다.

```python
from l4_orchestrator.browser_pages import BrowserPages
from l4_orchestrator.elements import ElementRegistry
from l4_orchestrator.page_events import PageEvents
from l4_orchestrator.tools.get_page_state import GetPageStateTool
from l4_orchestrator.page_content import PageContentReader
from l4_orchestrator.tools.click import ClickTool
from l4_orchestrator.sdk_registry import register_native_tools

def create_tools(state):
    elements = ElementRegistry(state, timeout_ms=element_timeout_ms)
    content = PageContentReader(state, timeout_ms=content_timeout_ms,
        max_text_bytes=text_limit_bytes, max_links=link_limit, max_links_bytes=links_limit_bytes)
    events = PageEvents(state, on_event=on_page_event)
    return {
        "get_page_state": GetPageStateTool(state, elements=elements, content=content),
        "click": ClickTool(elements, timeout_ms=action_timeout_ms, page_events=events),
        # 나머지 브라우저 Tool도 이 state/page/elements/events로 생성한다.
    }

pages = BrowserPages(default_state, create_tools=create_tools)
registry = register_native_tools({**pages.tools, **non_browser_tools})
```

위 변수의 시간·크기 한도·이벤트 처리·비브라우저 Tool은 기존처럼 호출측이 준비한다. 네트워크 수집, 스크린샷·HTML 저장의 설정과 저장 위치도 호출측이 그대로 제공한다. 현재 15개 브라우저 Tool을 모두 연결하는 실행 가능한 구성은 `tests/test_browser_pages.py`의 `Environment.create_tools`에 있다. 그곳의 숫자·로컬 주소·폴더는 검사 환경의 설정이며 운영 기본값이 아니다.

연결 객체는 같은 context에 이미 열린 Page와 이후 `page` 이벤트로 발견한 Page에 Tool 묶음을 한 번씩 만든다. 호출마다 해당 묶음을 재사용한다. 새 탭을 만들거나 화면 앞으로 가져오지 않으며, Tool 인스턴스의 Page를 실행 중 바꾸지 않는다. 동시에 같은 탭을 사용하는 작업의 직렬화는 기존 실행 환경 책임을 유지한다. SDK의 잠금 방식을 이번 변경에서 바꾸지 않았다.

### 저장과 네트워크 연결

여러 Page의 PNG·HTML·네트워크 저장 함수에 같은 기존 저장 객체를 전달할 수 있다. 기존 파일 정보에 각 Page의 ID가 보존된다. FileConnections의 producer는 그 저장 객체들을 그대로 사용한다. 네트워크는 factory 안에서 Page별 NetworkCapture를 붙이고 별도 목록에 보관한다. 실행 환경의 기존 마감 함수가 그 목록의 `capture.close()`를 기다리도록 연결한다. 이는 새 Agent Tool이 아니다.

**팝업을 처음 여는 HTTP 요청은 Page 발견 전에 시작될 수 있다.** 이 연결은 그 요청을 복구하거나 초기 응답을 전부 수집했다고 주장하지 않는다. Page별 NetworkCapture를 붙인 이후의 HTTP가 기존 수집 범위다. 브라우저 전체 초기 요청까지 보장하는 수집은 별도 범위다.

탭이 닫히면 열린 목록에서는 제외하지만, 그 탭의 Tool 묶음은 유지한다. 그래서 기존 `get_network_requests`로 확보한 기록을 계속 읽을 수 있다. 닫힌 탭에 대한 새 관측·행동은 기존 Tool이 거절한다. `detach()`는 이 연결의 새 Page 발견 리스너만 해제하며 탭·브라우저·파일을 닫거나 삭제하지 않는다.

## 오류와 호환성

| 경우 | 결과 |
|---|---|
| 연결에 없는 page_id | `PAGE_NOT_FOUND`, 다른 탭으로 대신 실행하지 않음 |
| 해당 Page의 Tool 구성 실패 | `PAGE_SETUP_FAILED`, 다른 탭으로 대신 실행하지 않음 |
| 연결을 거치지 않은 단일 Page Tool에 다른 page_id 지정 | `PAGE_MISMATCH`, 행동 전에 거절 |
| 다른 탭의 오래된 state_id/element_id | 기존 관측·요소 검증에서 거절 |
| 목록 조회에 특정 page_id 또는 state_id 지정 | 입력 오류. state_id는 null로 보내고, page_id는 생략하거나 null로 보냄 |
| 목록 수집 중 제목 조회 실패 | 해당 행의 title=null과 error 반환. 다른 탭 목록은 유지 |

기존 입력에서 생략한 page_id와 기본 scope는 준비 입력에 새 null/default 항목을 덧붙이지 않는다. 기존 단일 Page 구성을 그대로 쓸 수도 있다. 여러 탭으로 실제 요청을 전달하려면 위 BrowserPages 연결을 등록해야 한다.

## 검증 범위

아래 수치는 페이지 조회 통합 전 검증 기록이다. 현재 검사는 통합 입력과 15개 브라우저 Tool로 옮겼으며 새 결과는 [페이지 조회 통합 자료](../output/l4-page-query-consolidation-20261002/)에서 확인한다.

`tests/test_browser_pages.py`는 실제 Windows headless Edge와 통제된 로컬 HTTP에서 팝업 발견, 탭 B 행동, A의 관측 유지, 쿠키 공유, 17개 Tool의 잘못된 페이지 지정 거절, B의 조작·PNG·HTML·HTTP 기록, 닫힌 기본 탭과 구성 실패를 검사한다. 실제 SDK Runner·FunctionTool로 목록 → B의 요소 조회 → 클릭을 실행하고, 준비 입력·Store의 원 반환·다음 실행 Agent 입력을 대조한다. SDK 모델은 정해진 응답을 주는 시험용 모델이며 AWS 전송도 메모리 대역이다.

```powershell
$env:L4_BROWSER_CHANNEL = 'msedge'
.venv/Scripts/python.exe -m pytest tests/test_browser_pages.py -q -p no:cacheprovider --basetemp=.test-tmp/browser-pages-check
```

원문 증거는 검사 결과 폴더의 `popup-evidence.json`, `materials-evidence.json`, `sdk-pages-evidence.json`에 남는다. 실제 모델 판단·AWS 배포·Linux 브라우저 동작을 증명하는 검사는 아니다.

### 2026-10-02 독립 검토

고정 코드·새 검사 21개 파일의 사본과 SHA256을 `../output/l4-browser-pages-20261002/`에 보관했다. 독립 검토자가 실행 전후 해시 일치를 확인하고 새 검사 **6 passed (16.30s)**를 재현했다. 구현 측도 검토자의 `evidence-checks.json`을 열어 대조했다. 검토 범위에서 수정이 필요한 결함은 발견하지 못했다.

원문은 `.test-tmp/browser-pages-independent-3dec05ac20da43d38361d9189e3db996/`에 있다. B에서 생성한 HTML 651바이트·PNG 4,254바이트와 네트워크 기록 4건의 파일·해시·page_id가 일치했다. 네트워크 기록 한 건의 응답 본문은 `read_failed`로 남아 있으므로 기록 저장을 모든 본문 확보와 동일하게 보지 않는다.

SDK 증거는 목록 → B 요소 조회 → 클릭 → Store → 다음 실행 Agent 입력 경로다. B의 PNG·HTML 파일 검사는 별도로 실행했으며, 해당 B 파일의 SDK 이미지 전달과 AWS 게시까지 하나의 흐름으로 확인한 것은 아니다.

### 기존 동작 회귀 검사

기존 브라우저 17개 Tool의 관련 검사·관측 갱신·SDK 실행 검사를 함께 실행해 **387 passed (690.15s)**를 확인했다. 결과는 `.test-tmp/browser-pages-native-regression-5.xml`이며 원문 사본을 `../output/l4-browser-pages-20261002/`에도 보관했다. 새 다중 탭 6개는 구현 측과 독립 검토자가 각각 실행했다.

초기 검사에서는 새 테스트가 go_back 전에 필요한 관측을 생략한 문제와, 기존 SDK schema 검사가 state_id만 예상한 불일치가 있었다. 새 테스트의 호출 순서를 기존 Tool 규칙에 맞췄으며, 공유 SDK 작업에서 page_id 입력을 포함하도록 갱신한 현재 검사로 위 회귀 결과를 확인했다. 이를 서비스의 자동 관측·자동 재시도 추가로 해결하지 않았다.
