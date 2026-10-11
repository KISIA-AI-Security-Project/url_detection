# export_page — 현재 HTML 파일을 Bash로 전달

현재 SDK 연결은 [AGENTS_SDK.md](AGENTS_SDK.md)를 따른다. 아래 날짜가 붙은 초기 검증은 당시 범위이며, 현재 검사 자료는 [정리 검증 기록](../output/l4-sdk-cleanup-20261002/)에서 확인한다.

2026-10-02 승인한 범위를 구현했다. 같은 Page의 현재 주 문서를 UTF-8 HTML 파일 한 건으로 저장하고, 기존 Bash가 읽을 수 있는 상대 경로와 관측 정보를 반환한다. Agent가 요청할 때만 실행하며, HTML 전체를 Tool 반환에 복제하지 않는다.

## 실제 연결

```python
from l4_orchestrator.page_export_storage import LocalPageExportStore
from l4_orchestrator.tools.export_page import ExportPageTool

exports = LocalPageExportStore(bash_environment.cwd)
tool = ExportPageTool(
    state,  # 기존 브라우저 Tool과 공유하는 PageState
    timeout_ms=html_read_timeout_ms,
    max_html_bytes=html_file_limit_bytes,
    save_html=exports.save_html,
)
reply = await tool.execute({
    "action_id": action_id,
    "tool": "export_page",
    "target": None,
    "params": {},
    "context": {
        "job_id": job_id, "scenario_id": scenario_id,
        "step_id": step_id, "state_id": None,
    },
})
```

시간·용량은 호출측이 제공하는 양의 정수다. 기존 절대 폴더를 제공해야 하며 Tool이 운영 경로를 정하거나 root 폴더를 만들지 않는다. **exports.root와 BashEnvironment.cwd를 같은 폴더로 연결한다.** Tool은 별도로 생성된 Bash 객체의 설정을 알 수 없으므로 이 연결 조건은 실행 환경이 확인한다. 각 호출의 파일명은 새 식별자.html이며 이전 파일을 덮어쓰지 않는다.

입력에는 저장 경로나 파일명·형식·임의 JavaScript를 받지 않는다. 기존 실행 흐름에는 tool.as_port()를 연결한다. 같은 Page를 사용하는 호출은 실행부가 순서대로 수행한다.

## 읽고 저장하는 내용

현재 DOM의 documentElement.outerHTML과 존재하는 doctype을 함께 저장한다. doctype과 outerHTML 사이에 임의 줄바꿈을 넣거나 HTML을 정리·재작성하지 않고 UTF-8 바이트로 쓴다. 숨김 요소·inline script는 DOM에 있는 범위에서 포함한다.

이 파일은 원래 HTTP 응답, JavaScript 메모리·이벤트 리스너, DOM 속성에 반영되지 않은 현재 input.value, iframe/shadow 내부 문서, 외부 JS/CSS·이미지 파일을 함께 보존하는 자료가 아니다. 원래 화면을 오프라인으로 복원하는 기능도 아니다. 상대 주소는 원문에 남기며 확보 당시 url을 함께 반환한다. HTML에 적힌 form action·script src는 실제 전송·실행의 증거와 구분한다.

state_id=null이면 같은 호출 안에서 현재 관측을 수집한다. 명시 ID이면 해당 관측이 여전히 유효해야 한다. 수집 후 URL·DOM 지문·현재 상태를 대조한다. 상태 지문은 기존 PageState처럼 outerHTML 기준이며, 저장 파일 SHA-256은 doctype까지 포함한 전체 바이트 기준이다.

수집 중 상태가 달라지면 저장하지 않고 실패한다. 수집이 끝난 뒤 저장하는 동안 페이지가 이동·종료되면 이미 확보한 파일은 그 시점의 자료로 유지하고 after_state_id는 null로 반환한다. result.state_id는 파일 확보 시점의 ID다. 새 관측 후 click 등 다음 행동에는 기존 규칙대로 요소를 다시 조회한다.

## 결과와 실패

기존 Browser Tool의 status·실행 시각·상태 ID·observer_refs·error 형식을 사용한다. 성공 result에는 아래 값이 있다.

| 필드 | 의미 |
|---|---|
| file_ref | 완성된 파일의 참조. 파일 경로나 다운로드 URL이 아니다. |
| relative_path | 연결한 Bash 작업 폴더에서 읽는 파일명. 이 반환값을 명령의 파일 인자로 사용한다. |
| content_type | text/html; charset=utf-8 |
| size_bytes, sha256 | 완성한 HTML 바이트의 크기와 SHA-256 |
| page_id, state_id | 확보한 Page와 관측 |
| url, observed_at | 확보 당시 주소와 UTC 시각 |
| observation_scope | main_document_light_dom |

HTML 수집량이 max_html_bytes를 넘으면 HTML_TOO_LARGE로 거절한다. 잘린 파일을 만들지 않는다. 수집 제한 시간은 새 관측 준비까지 포함하며 디스크 저장 시간의 상한은 아니다. 브라우저의 진행 중인 읽기 자체가 시간 초과와 동시에 강제 종료된다는 보증은 없다.

주요 실패는 STATE_CHANGED, PAGE_CLOSED, BROWSER_CRASH, ACTION_TIMEOUT, HTML_TOO_LARGE, ARTIFACT_SAVE_FAILED다. HTML 문서가 아니면 UNSUPPORTED_DOCUMENT, UTF-8 변환 실패면 INVALID_PAGE_TEXT, 일반 읽기 오류면 INTERNAL_ERROR다. 시간 초과의 status는 timeout, 나머지는 failed다. 실패에는 result=null을 반환하며 닫힘·충돌은 recoverable=false다. 잘못된 요청/설정은 실행 전에 예외로 거절한다. 자동 재시도는 없다.

## 저장 완료와 실행부의 파일 등록

LocalPageExportStore는 바이트 쓰기와 파일 닫힘이 성공한 뒤에만 SavedPageExport와 내부 CompletedFile을 제공한다. 쓰기 실패 시 이번에 만든 불완전한 파일만 정리한다. Tool은 저장 함수가 반환한 크기·해시를 확보한 바이트와 대조한다. 사용자 정의 저장 함수가 실제 파일을 잘못 기록하거나 잘못된 완료 정보를 주었다면 ARTIFACT_SAVE_FAILED를 반환하며, 그 함수가 소유한 파일을 Tool이 임의 삭제하지 않는다.

내부 completed_file(file_ref)은 실제 절대 경로·내용 유형·크기·해시·관측 정보가 담긴 기존 CompletedFile을 반환한다. 실행부는 이 값을 L4Store.register_file에 연결할 수 있다. completed_files()는 이 저장 인스턴스에서 완성한 파일들의 목록이다. 두 메서드는 Agent Tool이 아니며 SDK·Store·AWS 호출을 수행하지 않는다.

저장 중 호출이 취소되면 이미 시작한 디스크 작업과 완료 정보 등록을 끝까지 확인한 뒤 CancelledError를 전달한다. 반복 취소로 디스크 작업만 남기지 않는다. **취소된 호출도 이미 완성된 파일은 남을 수 있으며**, 실행부는 completed_files()에서 확인해 보관·등록·정리 정책을 적용한다. 취소된 호출에는 성공 결과를 반환하지 않는다. 이 목록은 메모리 상태이며 프로세스 재시작 후 복구·전원 장애의 내구성을 구현한 것은 아니다.

HTML 보관본을 읽어 추출한 결과는 별도 값/파일로 다룬다. Bash가 파일을 수정해도 이전 sha256이 자동 변경되지는 않는다. 파일의 권한·게시·보관 기간은 실행 환경이 관리한다. 모든 파일 원문을 총괄에게 자동 전달하거나 보고 선별 규칙을 Tool이 정하지 않는다.

## 확인한 범위

새 검사 **15 passed (29.56s)**: 실제 Windows headless Edge, 통제된 로컬 HTTP, 실제 Git Bash를 사용했다. doctype 유무·UTF-8 원문·현재 DOM 범위, 같은 Page와 쿠키, 용량 경계, 오래된 관측, 수집 중 변경·이동·닫힘, 저장 중 이동·닫힘, 쓰기 오류·덮어쓰기 방지·반복 취소를 확인했다. 응답 없는 브라우저 통신·디스크 지연/실패는 주입한 검사다.

실제 click으로 form action을 initial에서 verify로 바꾼 뒤 현재 HTML451바이트를 저장했다. 기존 flow가 반환된 상대 경로를 Bash 입력으로 전달했고, 실제 Bash는 forms=[verify], scripts=[/scripts/form.js]와 같은 451바이트·SHA-256을 반환했다. 그 결과가 다음 시험용 총괄 입력에 동일하게 들어갔으며 원 페이지와 보관 파일은 변하지 않았다. [원 입력·HTML·파일 참조·Bash 출력·후속 입력](.test-tmp/export-35e877a3eb89465495655b566a20ae2e/test_click_export_bash_and_nex0/flow-evidence.json)을 대조했다. 이 파일은 시험 산출물이며 서비스가 매 호출마다 만드는 추가 JSON이 아니다.

기존 관련 회귀는 최초 **93 passed, 1 failed (56.75s)**였다. 실패는 기존 Bash의 늦은 시작 중 취소 후 프로세스 종료 확인 검사다. 서비스 코드 변경 없이 단독 **1 passed (0.62s)**, 기존 Bash 전체 **37 passed (7.31s)**로 재확인했다. 최초 실패 원인은 미확정이며 수정·해결했다고 표시하지 않는다. 재확인에는 기본 실행 계정의 1909 오류 때문에 일반 실행 환경을 사용했다. 나머지 기존 본문·PageState·flow 검사57개는 최초 실행에서 통과했다.

이 결과는 새 Tool의 로컬 파일 전달과 기존 실행 접점의 검증이다. 실제 SDK 모델의 조사 판단, Store 파일 등록·AWS 업로드·사용자 화면, Linux 브라우저에서의 이 Tool 실행은 확인하지 않았다. 이전 Bash Linux 검사를 export_page의 Linux 검증으로 옮겨 쓰지 않는다.

## 독립 검토

독립 검토자는 서비스 코드를 수정하지 않고 동일한 코드 상태에서 핵심 검사 **10 passed (28.10s)**를 확인했다. 실제 클릭 → HTML 파일 → Bash 추출 → 다음 시험용 총괄 입력, 용량 초과·오래된 상태·수집 중 페이지 변경, 저장 중 이동·닫힘, 쓰기 실패·반복 취소를 검토했다. 검토한 L4 사용 경로에서 수정 필수 문제를 발견하지 못했다. 검토 요청 자체나 검토자의 동의를 전체 서비스 완료의 증거로 사용하지 않는다.

구현 측도 [독립 실행의 원 입력·HTML·파일 참조·Bash 출력·후속 입력](.test-tmp/export-review-0bdfb048-a707-4611-9e43-b4c6eb4d869b/core-1/test_click_export_bash_and_nex0/flow-evidence.json)을 열어 확인했다. forms=[verify], scripts=[/scripts/form.js], 451바이트와 SHA-256이 일치했고 source_and_file_unchanged=true였다. 이 실행도 고정된 시험용 총괄을 사용했으며 실제 모델의 조사 판단을 검증한 것은 아니다.

검토 전후 아래 세 파일의 SHA-256이 같음을 확인했다. 이후 변경은 문서 정리뿐이다.

| 파일 | SHA-256 |
|---|---|
| src/l4_orchestrator/tools/export_page.py | 6063511A1648274B5AC71779C0F82C9B9CE7773B6F77FD92CE04AF499B27F7FE |
| src/l4_orchestrator/page_export_storage.py | CFE36B28E44430897A3843E9E5081803946B5F3582098F0820B36767D766CC3C |
| tests/test_export_page.py | 546DD55F5E9DDCEEA62363D68527F3DD06F77D689733AE56C7180F82BB30B6FF |
