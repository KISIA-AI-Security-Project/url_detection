# read_result — L4 업무·작업·결과 조회

현재 SDK 연결은 [AGENTS_SDK.md](AGENTS_SDK.md)를 따른다. 아래 날짜가 붙은 초기 검증은 당시 범위이며, 현재 검사 자료는 [정리 검증 기록](../output/l4-sdk-cleanup-20261002/)에서 확인한다.

`tools/read_result.py`는 실행부가 전달한 조회 함수로 같은 분석 건의 자료를 읽는다. 현재 구현은 Tool과 기존 ExecutionPort 연결까지다. SDK의 L4Store, 총괄 조회 연결, ACT 기록, DynamoDB/S3 전송은 이 파일이 구현하지 않는다.

## 입력과 반환

| 입력 | 읽는 내용 |
|---|---|
| `{"kind":"work","id":"W1","limit":10}` | 업무 정보와 현재 답/진행, 소속 작업의 작은 목록과 결과 참조 |
| `{"kind":"task","id":"T2","limit":10}` | 원래 배정·현재 상태·최종 참조, 수행한 행동 목록과 결과 참조 |
| `{"kind":"result","id":"result:ACT2","pointer":"/result/url"}` | Tool 실제 반환의 result.url 값 |
| `{"kind":"result","id":"report:T2","pointer":"/summary"}` | Agent 보고의 summary 값 |

10은 호출 형식의 예시다. 모델이 운영 한도를 정하지 않는다. 업무·작업 조회에 limit은 필수이며 다음 목록은 반환된 next_cursor를 cursor에 넣어 읽는다. 결과·보고 조회에 pointer는 필수이며 빈 문자열은 그 본문 전체다. work/task에는 pointer를, result에는 limit/cursor를 받지 않는다. 다른 job_id, 파일 경로, AWS 위치는 Tool 인자가 아니다.

Pointer는 기존 record_reader의 선택 연산을 재사용한다. `/result/a~1b/~0key/0`은 result 안의 `a/b`, 그 안의 `~key` 목록의 0번을 읽는다. 빈 문자열과 `/`는 다르다. `null`, `false`, `0`, 빈 문자열·빈 목록은 실제 값으로 보존하고 누락과 구분한다.

공통 반환은 다음 항목이다.

| 항목 | 의미 |
|---|---|
| status | 조회의 ok/error. 원래 실행의 성공 여부가 아님 |
| job_id, kind, id, pointer | 조회한 대상과 부분 위치. 목록 조회의 pointer는 null |
| data | work 조회는 `{work, tasks}`, task 조회는 `{task, actions}`, 본문 조회는 선택한 원래 JSON 값 |
| next_cursor | 남은 목록의 다음 위치. 마지막 목록과 본문 조회에서는 null |
| error | 성공은 null, 실패는 `{code, message}` |

조회 실패에서는 data와 next_cursor가 null이다. 실패했던 Tool 결과를 정상적으로 읽었다면 조회의 status는 ok이며 그 data 안의 원래 실패 상태·오류는 유지한다. 실행 중인 작업도 조회할 수 있고 실제 상태와 아직 없는 결과 참조를 보여준다.

## Store와 SDK 연결

~~~python
from l4_orchestrator.sdk_registry import register_native_tools, store_reader_binding

# 같은 job의 L4Store를 연결한다. native_tools에는 record_reader 등 기존 객체가 있다.
registry = register_native_tools(native_tools).replacing(store_reader_binding(
    store,
    max_list_items=caller_max_list_items,
    max_data_bytes=caller_max_data_bytes,
))
# registry를 run_l4에 전달한다.
~~~

`store_reader_binding`이 실제 Store 조회를 native `ReadResultTool`에 연결한다. 실행 Agent의 조회 범위는 자기 업무로 제한한다. 총괄은 같은 job의 자료를 조회한다. 이 연결은 이미 구현돼 있으며 별도 저장소를 만드는 예시가 아니다.

내부의 [read_result_source.py](src/l4_orchestrator/storage/read_result_source.py)가 업무·작업·결과 조회 함수에서 다음 `ReadResultView`를 제공한다.

- `ReadResultView(job_id, id, {"work": work_row, "tasks": task_summaries}, next_cursor)`
- `ReadResultView(job_id, id, {"task": task_row, "actions": action_summaries}, next_cursor)`
- `ReadResultView(job_id, result_ref, original_tool_return_or_report)`

work_row/task_row의 id는 조회 대상과 일치한다. task_row에는 work_id가 있어야 한다. 작업 요약은 id와 work_id, 행동 요약은 action_id·task_id·work_id를 포함한다. 목록에는 제목/실행 수단·상태·실제 시각·결과 참조·기록된 실패 이유를 필요한 범위로 담는다. 행동 결과 본문을 result/data/body로 목록에 넣는 응답은 거절한다. 원래 작업 배정의 지시·인자는 task_row에 보존한다.

조회 함수는 한 응답의 소속·본문·참조가 일치하는 자료를 제공한다. Tool은 분석 건·대상·소속·목록 한도와 T/ACT 숫자 순서를 확인하고 JSON 복사본을 반환한다. Tool 반환을 바꿔도 조회 원본은 바뀌지 않는다. 페이지를 이어 읽는 사이 진행 상태가 바뀔 수 있으며 과거의 단일 시점으로 전체 목록을 고정하지 않는다.

Cursor의 발급·대상 결합·권한 확인은 조회 함수가 맡는다. 다른 job/kind/id의 cursor 사용에는 `ReadResultLookupError("INVALID_CURSOR", message)`를 발생시킨다. 존재하지 않는 자료는 NOT_FOUND, 등록됐지만 결과/보고가 아직 없으면 RESULT_NOT_READY, 더 좁은 배정 범위에서 거절하면 FORBIDDEN을 같은 방식으로 전달한다. 아직 없는 결과를 기다리거나 다른 결과로 대체하지 않는다.

## 한도·오류·기록

max_list_items와 max_data_bytes는 생성 시 실행 프로그램이 제공하는 양의 정수다. max_data_bytes는 반환 data를 UTF-8 JSON으로 직렬화한 바이트 수다. 초과 목록 인자는 조회 전에 RETURN_LIMIT_EXCEEDED로 거절한다. 선택한 본문이나 목록이 너무 크면 VALUE_TOO_LARGE이며 중간에서 잘라 반환하지 않는다.

잘못된 Pointer와 없는 항목은 INVALID_POINTER / VALUE_NOT_FOUND다. 일관성이 맞지 않거나 JSON 값을 손실 없이 표현할 수 없는 응답은 INVALID_SOURCE_REPLY, 예기치 않은 조회 함수 실패는 SOURCE_UNAVAILABLE이다. 입력 자체의 불일치는 기존 prepare/입력 검사에서 거절한다. 취소는 CancelledError로 전파하며 자동 재시도하지 않는다.

총괄의 판단 중 조회는 SDK 연결부에서 자료 확인의 시작/종료를 표시하며 새 ACT·결과 참조를 만들지 않는다. 배정된 작업으로 실행하면 기존 공통 실행 연결부가 ACT·결과를 기록한다. 이 Tool에는 저장 함수가 없다.

결과 본문에 있던 네트워크 record_ref나 스크린샷 참조는 그대로 읽는다. 네트워크 상세 JSON은 기존 record_reader, 이미지 실물 전달은 기존 이미지 연결부가 담당한다. read_result가 참조의 파일을 자동으로 열거나 최초 스크린샷 전달에 추가 Tool 호출을 요구하지 않는다.

## 검증 범위 — 2026-09-30

새 조회 검사 30개와 기존 record_reader 검사 5개: **35 passed (0.62s)**. 기존 flow 및 기존 독립 검토 회귀 파일: **30 passed (0.90s)**. 이번 회귀 파일 실행은 원래 구현 작업에서 실행했으며 새 독립 검토자의 확인이라고 부르지 않는다.

업무/작업의 실제 소속, 숫자 순서·목록 이어 읽기·cursor 대상 거절, null/false/0/빈 자료와 누락, 진행 중·실패 상태, 원본 보존, UTF-8 바이트 한도, 입력 거절, 불일치 응답·조회 오류·취소를 확인했다. 실제 보관 L3 record를 기존 RecordReader로 읽은 반환을 주입하고 read_result의 선택값 → 기존 flow의 실제 실행 반환 → 다음 시험용 총괄 입력을 동일 값으로 대조했다. 이 검사는 현재 Tool과 제공 함수 사이의 조회 동작 증거다. SDK Store 구현·실제 모델 수신/판단·AWS 저장·사용자 화면 연동 증거는 아니다.
