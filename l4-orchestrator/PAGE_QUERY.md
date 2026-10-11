# get_page_state — 필요한 페이지 정보를 한 번에 읽기

페이지 상태·본문/링크·조작 요소의 공개 조회를 `get_page_state`로 통합했다. 이전 `get_interactable_elements`, `get_page_content`는 별도 Tool로 등록하지 않는다. 전체 Tool은 **18개**이며, 내부 수집용 Python 파일은 Tool 수에 포함하지 않는다.

## Agent의 입력

```json
{
  "target": null,
  "params": {"include": ["text", "elements"]},
  "context": {"page_id": "<실제 탭 ID>", "state_id": null}
}
```

`action_id`, `tool`, `job_id`, `scenario_id`, `step_id`는 SDK 실행부가 넣는다. Tool을 Python에서 직접 호출할 때는 기존처럼 이 항목들을 포함한다.

| params | 반환할 정보 |
|---|---|
| `{}` 또는 `{"include": []}` | 기본 상태: 페이지 ID·관측 ID·주소·제목·요소/폼 수·DOM 지문·관측 시각·범위 |
| `{"include": ["elements"]}` | 기본 상태 + 조작 가능한 요소 목록 |
| `{"include": ["text"]}` | 기본 상태 + 본문과 생략 여부 |
| `{"include": ["links"]}` | 기본 상태 + 링크 목록과 생략 여부 |
| `{"include": ["text", "links", "elements"]}` | 기본 상태 + 세 종류 모두 |
| `{"scope": "pages"}` | 같은 BrowserContext의 열린 탭 목록. DOM 관측 ID는 발급하지 않음 |

`include` 순서는 수집 순서를 지정하지 않는다. 중복 항목·지원하지 않는 이름은 거절한다. `visible_only`는 기본 true이며, elements를 요청할 때 false로 지정하면 숨겨진 지원 요소도 조회한다. 이 설정은 본문·링크의 표시 규칙을 바꾸지 않는다. 목록 조회(scope=pages)는 include를 비워 두고 page_id/state_id도 null로 보낸다.

`context.page_id` 생략/null은 연결 시 정한 기본 탭이다. `context.state_id`는 null이면 새 관측을 만들고, ID를 주면 아직 유효한 그 관측을 기준으로 읽는다. 탭·쿠키·페이지를 다시 만들지 않는다.

## 같은 관측을 기준으로 반환

새 상태를 한 번 수집하고, 요청한 본문·링크와 요소를 그 state_id에 맞춰 읽는다. 반환의 `result`에는 기본 상태와 선택한 자료가 함께 들어간다. elements가 있으면 그 목록의 element_id와 **같은 응답의 state_id/page_id**를 후속 click·fill 등에 사용한다.

수집 중 DOM 변경·페이지 이동·닫힘을 감지하면 일부 자료만 성공으로 내보내지 않고 `result=null`과 오류를 반환한다. elements를 포함한 조회가 실패하거나 취소되면 이전 목록도 그 실패한 조회의 행동 대상으로 남기지 않는다. 자동 재시도하지 않는다.

이것은 여러 읽기를 같은 관측 기준으로 확인하는 방식이다. 모든 픽셀·JavaScript 메모리·네트워크 상태를 한순간에 고정한다는 뜻은 아니다. `observed_at`은 기본 조회에서는 상태 수집 시각, 추가 자료가 있으면 마지막 수집기의 시각이다. 각 읽기는 기존 DOM 지문·변경 감지 규칙을 사용한다.

본문만 기존 state_id로 읽을 때는 요소 목록을 다시 발급하지 않는다. 반면 state_id=null로 새 관측을 만들면 이전 관측의 요소로 바로 행동할 수 없다. 다음 행동에 요소가 필요하면 그 호출에 elements도 포함한다.

## 필요한 자료만 수집

- elements가 없으면 요소 수집기와 요소 목록 발급을 실행하지 않는다.
- text/links가 모두 없으면 본문 수집기를 실행하지 않고 관련 필드를 덧붙이지 않는다.
- text 또는 links 중 하나만 요청하면, 다른 쪽의 기존 본문 반환 필드들은 null이다. 요청했지만 없는 내용(`""`, `[]`)과 구분한다.
- 본문 UTF-8 바이트·링크 수·링크 JSON 바이트 제한과 각각의 생략 표시를 유지한다. 한도는 호출측이 정한다.
- 스크린샷·HTML 파일·네트워크 조회는 각 Tool로 명시적으로 요청한다. 이 조회는 파일을 저장하지 않는다.

본문·링크의 구체적인 범위는 [PAGE_CONTENT.md](PAGE_CONTENT.md)를 따른다. 기본 상태에는 이미 필요한 요소/폼 수 계산이 있으므로 elements 미요청이 모든 DOM 요소 검사를 생략한다는 뜻은 아니다.

## 실행 환경의 연결

```python
from l4_orchestrator.elements import ElementRegistry
from l4_orchestrator.page_content import PageContentReader
from l4_orchestrator.tools.get_page_state import GetPageStateTool

elements = ElementRegistry(state, timeout_ms=element_timeout_ms)
content = PageContentReader(
    state, timeout_ms=content_timeout_ms,
    max_text_bytes=text_limit_bytes,
    max_links=link_limit, max_links_bytes=links_limit_bytes,
)
query = GetPageStateTool(state, elements=elements, content=content)
native_tools = {"get_page_state": query}
```

세 객체는 **같은 PageState 인스턴스**를 사용해야 한다. click·fill 등에도 위 elements를 전달한다. PageState·ElementRegistry·본문 수집기의 제한 시간은 각 단계에 적용되며 전체 조회 시간 한도를 새로 도입한 것은 아니다. 실행 환경의 작업 한도는 기존 SDK 책임이다.

여러 탭 연결은 [BROWSER_PAGES.md](BROWSER_PAGES.md)의 `create_tools(state)`에서 같은 구성을 탭마다 만든다. 예시 변수는 호출 프로그램이 제공하는 설정이며, Tool이 운영 시간·크기 제한을 임의로 정하지 않는다.

SDK의 `allowed_tools`에는 `get_page_state`를 한 번 등록한다. 이 이름은 기본 상태·본문·링크·요소를 읽을 수 있는 하나의 허용 단위다. 이전 두 이름은 더 이상 등록되지 않으므로 기존 배정 생성 코드의 이름과 입력도 위 형식으로 바꿔야 한다. 과거 Store에 저장된 Tool 이름과 반환은 고쳐 쓰지 않는다.

## 코드와 확인 범위

| 파일 | 역할 |
|---|---|
| [tools/get_page_state.py](src/l4_orchestrator/tools/get_page_state.py) | 하나의 공개 입력, 선택 수집, 공통 응답, 탭 목록 |
| [page_state.py](src/l4_orchestrator/page_state.py) | 관측 발급과 유효성 |
| [elements.py](src/l4_orchestrator/elements.py) | 원래 요소의 ID와 동작 대상 확인 |
| [page_content.py](src/l4_orchestrator/page_content.py) | 지정 관측을 기준으로 제한된 본문·링크 수집 |
| [sdk_registry.py](src/l4_orchestrator/sdk_registry.py) | 통합 이름·입력으로 SDK 등록 |

선택 수집·도중 변경·실패·실제 SDK 전달 검사는 `tests/test_page_query.py`, 탭 선택과 실행 Agent 연결은 `tests/test_browser_pages.py`에 있다. 검사 결과와 실제 반환은 [이번 변경의 검증 자료](../output/l4-page-query-consolidation-20261002/)에 보관한다. 통제된 모델 응답·로컬 브라우저 검증은 실제 모델의 판단 품질이나 AWS 운영 검증과 구분한다.
