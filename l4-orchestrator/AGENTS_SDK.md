# L4 Agents SDK 실행 연결

구현 기준은 [심층조사 설계안](https://app.notion.com/p/3ea3dea100f7816fa650eaab3ee715e6), [Store 구현](https://app.notion.com/p/3ec3dea100f78186a0d7faf09913d437), [백엔드 인계](https://app.notion.com/p/3ec3dea100f78134bbf7e815a7c8fbd0)와 `../docs/l4-sdk-implementation-handoff-20261001.md`의 마지막 합의다.

현재 실행 진입점은 `l4_orchestrator.run_l4`다. 기본 실행 의존성은 `openai-agents==0.22.3`이다. 이전 `flow.py`·전용 이미지 전송 코드·LangGraph 의존성은 제거했다. native Tool의 공통 정의와 실제 기능 검사는 유지하며, 실행 연결 검사를 SDK 경로로 옮겼다. 정리 전 사본은 `../output/l4-sdk-cleanup-20261002/before/`에 있다.

**현재 검증 범위:** SDK Runner·FunctionTool 반복과 실제 로컬 브라우저·Bash·파일의 통제 검사를 유지한다. 2026-10-06에는 실제 Fast 입력·L4 최초 캡처 → Astra 총괄 → DynamoDB·S3 저장·조회도 확인했다. Rust는 인증된 서비스의 심층분석 버튼으로 시작했으며 실제 SSE 백엔드의 완료 이벤트를 확보했다. 두 실제 사례의 Task·ACT는 0건이므로 실행 Agent·추가 Tool 조사·한도·모델 호출 실패의 실제 AWS 검증으로 확대하지 않는다. 원본 자료는 [AWS 검증 기록](../output/l4-aws-runtime-20261006/AWS-VERIFICATION.md)에 있다.

## 호출자가 준비할 것

| 입력 | 책임 |
|---|---|
| `job_id`, `initial_findings`, `previous_judgment` | 기존 분석 건과 실제 앞선 자료. `initial_findings`의 의미·구조는 호출자가 전달하며 여기서 재요약하지 않는다. |
| `initial_screenshot` | L4가 직접 접속해 저장한 첫 PNG의 기존 메타데이터. `FileConnections`가 실제 이미지 바이트를 총괄의 첫 입력에 연결한다. |
| `model_name`, `executor_model` | 총괄·실행 모델 이름 또는 SDK `Model` 객체. 기본 모델을 임의로 선택하지 않는다. |
| `ExecutionLimits` | 자료량·전체 총괄 호출 횟수·Runner 반복·작업 실행시간·조사시간. 숫자는 호출자가 정한다. |
| 기존 Tool 객체 | Page 또는 BrowserPages 연결, Bash 환경, 원본 record와 각 Tool의 기존 한도·허용 조건을 준비한다. |
| `L4Store`, `AwsPublisher` | 같은 job의 Store 하나와 그 Store를 사용하는 publisher 하나. |
| `FileConnections` | 완성 파일을 조회할 저장 객체, 네트워크 수집 종료 함수, PNG 읽기 객체. |
| 선택 `RunConfig` | 모델 공급자·추적 등 SDK 실행 설정. 오프라인 검사에서는 추적도 끈다. |

```python
from l4_orchestrator import run_l4
from l4_orchestrator.sdk_registry import register_native_tools, store_reader_binding
from l4_orchestrator.sdk_files import FileConnections

# 아래 객체·수치는 실제 실행 환경이 준비한다.
registry = register_native_tools(native_tools).replacing(store_reader_binding(
    store, max_list_items=read_result_max_items, max_data_bytes=read_result_max_bytes,
))
files = FileConnections(
    producers=(screenshot_store, network_store, page_export_store),
    close_callbacks=(network_capture.close,),
    screenshots=screenshot_store,
)
final = await run_l4(
    job_id=job_id, initial_findings=initial_findings,
    previous_judgment=previous_judgment,
    model_name=manager_model, executor_model=executor_model,
    execution_limits=execution_limits, initial_screenshot=initial_screenshot,
    registry=registry, store=store, publisher=publisher, files=files,
)
```

`native_tools`는 이름 → 이미 생성한 기존 Tool 객체의 목록이다. 총괄의 `record_reader`를 반드시 포함한다. `store_reader_binding()`은 같은 Store에 조회를 연결하며, 실행 Agent의 조회는 자기 업무로 제한한다. 총괄이 명시해 준 `input_refs`의 본문은 별도로 Agent 입력에 전달한다.

## 실행과 기록

1. publisher가 AWS 시작 기록을 확인한다.
2. 총괄 Runner가 입력과 이전 이력을 읽고 `ManagerTurn`을 반환한다. 판단 중 조회에는 ACT가 생기지 않는다.
3. 반환 전체의 ID·허용 Tool·작업 관계를 확인하고 Store에 배정을 등록한다. 배정이 잘못됐으면 일부를 실행하지 않고 다음 총괄 입력에 이유를 준다.
4. 직접 Tool 작업과 실행 Agent가 같은 `run_tool()`로 ACT를 발급받는다. ACT에는 원래 `arguments_json`과 실제 준비 입력이 따로 남는다.
5. 기존 Tool이 반환하면 완성 파일을 연결하고 원본 반환을 저장한다. Agent가 여러 Tool을 쓰면 각 ACT와 마지막 `report:Tn`이 구분된다.
6. `review_after`가 성립하면 아직 전달하지 않은 종료 작업 결과만 선택한다. 총괄 호출 중 도착한 다른 결과는 다음 선택까지 Store에 남는다.
7. 총괄이 종료하면 새 작업·ACT를 막고 이미 시작한 결과와 파일 정리를 기다린다. 최종 결과를 저장하고 AWS의 마지막 저장 확인 뒤 반환한다.

### 실행 한도와 총괄 호출 실패

2026-10-02 사용자의 명확한 지시에 따라, **실행 한도 도달은 총괄 판단 없이 중단하는 이유가 아니다.** 전체 총괄 호출 횟수 중 마지막 한 번을 최종 판단에 남겨 두며, 조사 시간 한도에 도달해도 이미 실행한 Tool의 반환을 기록한 뒤 총괄에게 확보한 자료와 한도 도달 사실을 전달한다. 마지막 판단에서는 새 작업을 배정하지 않고 업무의 답과 최종 결과를 작성한다. 이 Runner 안에서도 마지막 모델 응답 한 번은 답을 작성하는 데 남긴다. 그 전까지는 조회할 수 있지만 마지막 응답에서는 조회 Tool을 제공하지 않는다. `runner_turns=1`이면 확보한 입력만으로 바로 최종 답을 작성한다. 정리와 마지막 판단 시간은 추가 조사 시간과 구분한다.

Agent 반복을 마친 뒤 아직 보고가 없는 작업은 최종 판단을 기다리는 `waiting` 상태로 기록한다. 총괄은 `read_result`로 그 작업의 실제 행동·반환을 확인할 수 있다. 총괄의 종료 결정 뒤에만 남은 작업을 `ended_by_manager`로 마무리한다. 개별 작업 시간 한도는 그 작업 결과로 남겨 기존 `review_after`에 따라 총괄이 읽는다.

총괄 모델 호출 자체가 실패한 경우에는 확보된 기록·파일의 전송을 마무리하고 원래 호출 오류를 호출부에 반환한다. `seal_without_final()`은 이때 최종 결과를 만들지 않고 기록만 마감한다. META의 `finalizing`과 비어 있는 `final_result_ref`를 유지하며 `completed`로 표시하지 않는다. Store나 영구 전송 오류가 있으면 정상 저장 완료로 보고하지 않고 확인되지 않은 기록을 유지한다.

`manager_input_bytes`는 실제 이력·새 입력의 UTF-8 크기를 검사한다. 자료가 한도를 넘었다고 원문이나 이력을 임의로 삭제하지 않는다. 전달 자료 선택·축소 정책과 `initial_findings` 내용은 설계에서 추후 결정하도록 둔 경계다.

### 작업 보고와 근거 참조

실행 Agent의 보고는 `report:Tn`에 원문을 보관한다. 보고가 인용한 `result:`·`report:` 참조를 Store에서 찾지 못해도 보고 저장을 막지 않는다. `summary`·`findings`·`limits`는 유지하고, 해당 경우에만 코드가 `reference_errors: [{ref, reason}]`를 함께 저장한다. 다음 총괄 입력과 `read_result`에서 같은 내용을 읽는다. 이는 저장된 결과를 찾을 수 있는지에 대한 정보이며 보고의 분석 내용이 틀렸다는 판정이 아니다.

Page 잠금은 브라우저 작업 전체를 보호한다. Agent 내부 Tool 호출에서 같은 잠금을 다시 잡지 않는다. SDK의 `parallel_tool_calls=False`와 작업 사이의 병렬 실행은 별개다.

## 기존 Tool 입력을 연결하는 방법

페이지 조회는 [get_page_state 하나로 통합](PAGE_QUERY.md)했다. `allowed_tools`와 native 등록에는 이 이름을 한 번 넣고, 모델이 `params.include`로 text·links·elements를 선택한다. 이전 get_interactable_elements/get_page_content 이름과 입력을 생성하는 호출부는 새 형식으로 바꿔야 한다. 이 통합은 페이지 정보 조회를 하나의 허용 단위로 묶으며, 기존에 저장한 반환·배정 기록을 다시 쓰지는 않는다.

`sdk_registry.py`는 native Input 정의에서 모델 안내와 SDK schema를 함께 만든다. 모델 입력의 위치·허용값·선택값·기본값은 기존 정의를 유지한다. 그래서 SDK의 strict schema 변환으로 선택 인자를 새 필수값으로 바꾸지 않고, 기존 `port.prepare()`가 입력을 검사한다.

브라우저 Tool의 모델 입력:

```json
{"target":null,"params":{},"context":{"state_id":null}}
```

호출 시 코드가 `action_id`, `tool`, `context.job_id`, `context.scenario_id=Tn`, `context.step_id=ACTn`만 보충한다. `record_reader`와 `bash`에는 브라우저 context를 붙이지 않는다. `read_result`의 work/task/result 입력도 native 위치를 유지한다. `context.page_id`가 있으면 그대로 보존하며, Page 선택은 [기존 브라우저 연결](BROWSER_PAGES.md)이 담당한다.

`sdk_tools.py`는 Store 실패와 종료 신호를 모델용 오류 문자열로 삼키지 않는다. SDK 0.22.3이 Tool 예외를 `UserError`로 감싸는 경우에도 원래 `ExecutionEnded`·`StoreError`를 구분해 전달한다.

## 파일과 이미지

PNG·네트워크·HTML 저장 객체가 `completed_files()`로 기존 참조와 완성 파일의 경로·크기·해시를 제공한다. `FileConnections`가 Tool 반환 뒤 같은 이벤트 루프에서 Store에 등록한다. native 파일 저장 함수 안에서 Store를 변경하지 않는다.

스크린샷의 경우 JSON 메타데이터와 함께 실제 PNG를 `ToolOutputImage`로 실행 Agent에게 전달한다. 통제된 브라우저 검사에서 다음 모델 입력의 PNG와 저장 파일의 SHA-256을 비교한다. 네트워크 수집은 기존 `close()`로 저장을 마친 뒤 마지막 파일들을 등록한다.

## 검증 재현

```powershell
.venv/Scripts/python.exe -m pip install -e '.[test,browser,aws]'
$env:L4_BROWSER_CHANNEL = 'msedge'
.venv/Scripts/python.exe -m pytest tests/test_sdk_runtime.py tests/test_sdk_browser.py -q
```

공용 임시 폴더 접근이 제한된 환경에서는 `--basetemp`에 작업 폴더 안의 **새 폴더**를 지정한다. 검증 수치와 고정 사본은 `../output/l4-sdk-implementation-20261002/`에 보관한다. 기존 Store의 실제 AWS 검증은 이전 저장 모듈의 증거이며 새 SDK 전체 경로의 운영 증거로 재사용하지 않는다.

## 서비스 연결과 남은 검증

AWS 실행 환경은 `aws_runner.py`가 실제 Builder 최종 모델 본문·Judgment 전체·L4 첫 캡처와 모델·한도·Tool·Store를 준비한다. `aws_start.py`·`aws_query.py`와 인증 BFF·SSE가 서비스에 연결된다. 각 구현과 공개 응답의 책임은 [AWS_SERVICE.md](AWS_SERVICE.md)를 따른다.

- 승인한 모델은 총괄·실행 모두 Astra/high, 한도는 총괄 6회·작업 Runner 8회·추가 조사 180초다. `manager_input_bytes`·`task_seconds`는 설정하지 않는다. 원문을 임의로 줄이는 정책은 추가하지 않았다.
- 실제 두 사례에서는 총괄이 바로 종료했다. 실행 Agent의 실제 모델 호출과 추가 Tool 조사가 있는 AWS 실행, 실제 한도 도달과 모델 호출 실패는 아직 확인하지 않았다.
- 공개 응답 수정 후 실제 프론트의 SSE 완료 수신·펼치기를 확인했다. Task·ACT가 있는 기존 SDK 기록의 화면 관계·원래/실제 입력·결과 링크·펼침 유지도 별도 재생과 독립 대조를 마쳤다.

오프라인 재생과 실제 모델·AWS·서비스 검증은 각각의 증거로 구분한다. 이전 Store 단독 검증과 통제된 SDK 기록을 전체 서비스 운영 증거로 대신하지 않는다.
