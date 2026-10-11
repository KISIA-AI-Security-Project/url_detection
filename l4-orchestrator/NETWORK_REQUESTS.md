# 네트워크 요청 조회와 상세 자료 보관

현재 SDK 연결은 [AGENTS_SDK.md](AGENTS_SDK.md)를 따른다. 아래 날짜가 붙은 초기 검증 기록은 당시 범위이며, 현재 실행 검사 결과는 [정리 검증 기록](../output/l4-sdk-cleanup-20261002/)에서 확인한다.

`get_network_requests`는 같은 Page에서 관측한 HTTP 요청의 목록과 상세 자료 참조를 읽는다. 네트워크 수집 연결은 페이지를 열거나 클릭하기 전에 한 번 붙이고, 브라우저를 쓰는 동안 유지한다. Tool을 조회할 때마다 수집을 다시 시작하지 않는다.

예를 들어 `버튼 클릭 → 브라우저의 POST 요청 관측 → 헤더·본문 확보 및 로컬 저장 → 요청 목록과 참조 조회 → 필요한 본문만 read_record로 조회`로 이어진다. 저장할 상세 자료와 Agent에 바로 반환할 작은 목록을 구분한다. 총괄 보고의 선별은 이 Tool이 수행하지 않는다.

## 파일과 연결

| 파일 | 역할 |
|---|---|
| `tools/get_network_requests.py` | 목록·증분 갱신·저장 참조 조회 및 기존 as_port 접점 |
| `network_capture.py` | 같은 Page의 HTTP 요청·응답·완료·실패를 관측하고 정한 범위의 상세 자료를 확보 |
| `network_storage.py` | 호출측이 지정한 폴더에 완료된 JSON 한 건을 저장하고 같은 Reader에 등록 |
| `tools/record_reader.py` | 등록된 record의 필요한 항목만 읽음. 신뢰된 프로그램용 register를 추가했으며 Tool 입력으로 노출하지 않음 |

```python
from l4_orchestrator.network_capture import NetworkCapture
from l4_orchestrator.network_storage import LocalNetworkStore
from l4_orchestrator.tools.get_network_requests import GetNetworkRequestsTool
from l4_orchestrator.tools.record_reader import RecordReader

reader = RecordReader({}, max_data_bytes=read_limit_bytes)
store = LocalNetworkStore(configured_network_dir, reader, max_record_bytes=record_limit_bytes)
capture = NetworkCapture(
    state, page_events=page_events, save_record=store.save,
    max_requests=request_limit, max_body_bytes=body_limit_bytes,
    max_total_body_bytes=total_body_limit_bytes, capture_timeout_ms=read_timeout_ms,
    response_body_types=selected_response_types,
)
network_port = GetNetworkRequestsTool(capture, max_return_items=query_limit).as_port()
record_port = reader.as_port()
# native_tools에 get_network_requests, record_reader로 등록하고 register_native_tools에 전달
# Page를 이용하는 작업 종료 시 await capture.close()
```

위 변수들은 호출 프로그램이 제공하는 설정이다. 저장 폴더는 기존의 절대 경로여야 하며 코드가 운영 폴더를 선택하거나 생성하지 않는다. 같은 Reader를 계속 사용해야 새로 등록한 참조를 조회할 수 있다. PageState·PageEvents도 같은 인스턴스를 사용한다. 실행 업무의 허용 범위는 기존 authorize 연결에서 확인한다.

## Tool 입력

```json
{
  "action_id": "read-network-1",
  "tool": "get_network_requests",
  "target": null,
  "params": {"capture_id": null, "after_sequence": 0, "limit": 20},
  "context": {
    "job_id": "analysis-example", "scenario_id": "inspect-form",
    "step_id": "read-network", "state_id": null
  }
}
```

limit는 필수 양의 정수이고 호출측 max_return_items를 넘으면 명시적으로 거절한다. 첫 조회는 after_sequence=0으로 현재까지 관측한 목록을 읽는다. 후속 조회는 반환받은 capture_id와 next_after_sequence를 넘긴다. 이전 수집 연결의 ID, 미래 순번, bool·문자열 한도는 거절한다. 네트워크 자료는 DOM 상태 ID로 조회하지 않으므로 context.state_id는 null이어야 한다.

이 Tool은 브라우저를 조작하거나 DOM 관측을 수집·무효화하지 않는다. 닫힌 Page에서 이미 관측한 이력도 조회할 수 있다. 반환의 before_state_id/after_state_id는 null이고 provenance는 existing_material이다. 새 HTTP 요청을 보내거나 이전 요청을 재실행하지 않는다.

## 작은 반환과 저장 자료

목록 항목에는 요청 ID·URL·GET/POST 등 방식·리소스 유형·관측 시각·갱신 순번, 응답 코드·실패 이유·통신 상태, 이전 리다이렉트 요청 연결과 상세 자료 준비 상태가 있다. 원문 헤더·본문은 목록에 복제하지 않는다.

| 상태 | 의미 |
|---|---|
| network_state=pending | 요청 시작을 관측했고 응답·완료는 아직 확인하지 못함 |
| response_received | 응답 코드와 헤더 수신 사건을 관측함. 본문 다운로드 완료와는 다름 |
| completed | requestfinished를 관측함. HTTP 404/500도 이 상태일 수 있음 |
| failed | requestfailed를 관측함. HTTP 오류 코드와 구분 |
| unfinished | 수집이 끝날 때 완료·실패를 확인하지 못함. 임의로 실패로 바꾸지 않음 |
| detail_state=pending | 상세 자료 확보·저장이 아직 준비되지 않음 |
| saved | 저장 연결부가 완료와 등록을 반환하고 내용 해시가 일치함. record_ref/source_sha256 제공 |
| failed / cancelled | 상세 자료 처리 실패·취소. 성공한 참조를 만들지 않음 |

완료된 상세 record는 `l4-network-1` 형식의 JSON이다. 요청·응답 헤더를 중복 항목도 유지하는 배열로 저장하고, 요청 본문과 선택한 응답 유형의 본문을 보관한다. response_body_types는 호출측이 지정한다. 예를 들어 document/fetch/xhr를 선택하면 이미지·영상 응답 본문을 일괄 저장하지 않는다. 선택하지 않은 응답도 기본 요청 기록과 확보한 헤더는 남는다. 요청에 담긴 본문은 요청 시작 때 확보하며 유형에 관계없이 크기 한도를 적용한다.

본문은 UTF-8로 손실 없이 표현할 수 있으면 encoding=utf-8/data=문자열, 그렇지 않으면 encoding=base64/data=바이너리 표현으로 저장한다. 양쪽 모두 원래 확보한 바이트로 복원할 수 있고 byte_length와 SHA-256을 남긴다. JSON 본문을 다시 파싱해 숫자·공백·중복 키를 바꾸지 않는다. 이 원문은 **Playwright가 노출한 자료**이며 HTTP 패킷 전체·압축 전송 바이트·실제 서버 수신을 증명하는 자료라고 확대하지 않는다.

| 본문 status | 의미 |
|---|---|
| captured | 실제 바이트를 확보함. data=""/byte_length=0은 확보한 빈 본문 |
| unavailable | 요청 본문을 API에서 받지 못함. 미노출과 실제 본문 부재를 단정해 구분하지 않음 |
| not_selected | 호출측이 해당 응답 유형의 본문 수집을 선택하지 않음 |
| body_limit / total_limit | 개별·전체 보존 한도 때문에 본문을 보존하지 않음 |
| read_failed / timeout | 읽기 실패·제한 시간 초과. 빈 문자열로 대체하지 않음 |
| unfinished | 완료를 확인하지 못해 전체 응답 본문을 수집하지 않음 |

응답 사건을 관측하지 못했으면 record의 response는 null이며 목록의 response_body_status는 no_response다. 이것을 서버가 아무것도 받지 않았다는 판단으로 해석하지 않는다. 헤더 읽기도 captured/read_failed/timeout으로 구분한다.

저장한 자료가 필요하면 다음과 같이 같은 Reader를 사용한다.

```json
{"record_ref": "목록에서 받은 실제 참조", "pointer": "/request/body/data"}
```

다른 조회 위치는 `/request/headers`, `/response/headers`, `/response/body`다. 본문 전체 객체를 읽으면 보존 상태·인코딩·길이·해시까지 확인할 수 있다. 자료가 준비되기 전에 참조를 추정해서 요청하지 않는다. Reader 반환 한도를 넘는 자료는 VALUE_TOO_LARGE이며 임의로 자르지 않는다.

## 진행 중 요청과 증분 조회

같은 URL로 두 번 요청해도 서로 다른 request_id다. 리다이렉트의 각 HTTP 요청도 별도로 기록하고 이전 요청의 ID·URL을 연결한다. 수집을 늦게 시작하거나 한도 때문에 이전 요청이 빠졌으면 이전 요청 ID가 없을 수 있다.

sequence는 요청 시작 순서가 아니라 **그 요청의 최근 상태 갱신 순번**이다. 진행 중 목록을 읽은 뒤 요청 완료 또는 저장 완료가 생기면 같은 요청 ID가 새 순번으로 다시 반환된다. 호출측은 ID로 기존 표시를 갱신한다. 순번은 capture_id 안에서만 비교한다.

페이지로 일부만 반환했다면 next_after_sequence는 실제 반환한 마지막 항목의 순번이다. has_more가 true면 이어서 조회한다. 모든 중간 사건 이력을 제공하는 방식은 아니며, 각 요청의 최신 상태를 증분 조회한다.

observed_during_action_id는 요청 시작을 관측한 PageEvents 호출 구간이다. 이 필드나 시간상 가까움만으로 특정 클릭이 통신을 일으켰다고 확정하지 않는다. 늦은 요청은 이 값이 null일 수 있다.

## 수집 범위와 한도

범위는 지정 Page의 HTTP/HTTPS 사건이다. Page를 열기 전에 붙이면 그 문서 이동부터 관측한다. 붙이기 전의 통신을 과거 기록처럼 복원하지 않는다. 다른 Page·팝업·Service Worker·WebSocket 등의 모든 통신이나 OS 패킷을 관측했다고 주장하지 않는다. 하위 프레임의 요청은 그 Page 사건으로 제공되는 범위에서 포함될 수 있다.

max_requests까지 요청별 상태를 유지하며 자동 초기화·과거 항목 삭제는 하지 않는다. 이후 새 요청이 빠지면 dropped_requests와 request_limit_reached로 표시한다. capture_started_at/stopped_at/active를 반환해 빈 목록의 관측 구간도 알 수 있다.

max_body_bytes와 max_total_body_bytes는 **보존하는 본문 바이트** 한도다. 응답 읽기는 하나씩 수행하고 capture_timeout_ms로 제한한다. Content-Length로 이미 한도 초과를 알면 본문 읽기를 생략하고, 실제 확보한 본문도 길이를 확인한다. Playwright body()는 본문 전체를 읽으므로 이 한도를 브라우저·읽기 순간의 강제 메모리 한도라고 주장하지 않는다. 압축 응답의 Content-Length도 실제 확보한 본문 길이로 기록하지 않는다. 저장할 JSON 전체는 LocalNetworkStore의 max_record_bytes로 다시 제한한다. 기록 수·본문 크기·완료된 기록 크기를 모두 호출측에서 정한다.

capture.flush(timeout_ms=...)는 그때 알고 있는 작업의 완료를 제한 시간 동안 기다리는 프로그램용 기능이다. 반환 false는 아직 작업이 남았다는 뜻이다. 조회 Tool은 이를 자동 호출하거나 모든 미래 통신이 끝날 때까지 기다리지 않는다.

capture.close()는 수집 리스너를 떼고 진행 중 요청을 unfinished로 표시하며 이미 맡긴 상세 처리 작업을 마친다. 브라우저 Page를 닫거나 HTTP 요청을 취소하지 않는다. 사용자 제공 저장 연결부의 종료 시간은 호출 프로그램이 관리한다. LocalNetworkStore는 저장 호출이 반복 취소돼도 이미 시작한 디스크 쓰기와 Reader 등록을 하나의 보호된 작업으로 끝낸 뒤 취소를 전파한다. 취소된 호출에는 성공 참조를 반환하지 않는다. 강제 프로세스 종료나 실행 루프 자체 종료까지 보장하는 내구성은 구현하지 않았다.

완료 JSON은 게시한 뒤 추가 기록을 이어 쓰지 않는다. 그래야 Reader가 등록한 해시와 계속 일치한다. 파일은 로컬에 남지만 프로세스 재시작 후 참조 복원·보관 기간·삭제·AWS 업로드는 구현하지 않았다. 실제 저장 폴더·운영 한도·보관 기간을 이번 코드가 결정하지 않는다. 사용자 진행 정보의 AWS 경로, Agent의 보고 선별, 기존 L0–L3/Builder 연결과 의미 판단은 별도 책임이다.

## 검증 범위

`tests/test_network_requests.py`는 실제 headless Edge와 통제된 로컬 HTTP 서버를 사용한다. 서버의 POST 수신 바이트→저장 JSON→Reader 반환→기존 flow 입력·결과와 후속 시험용 총괄 입력을 대조한다. 조회에 원문이 섞이지 않은 뒤 필요한 본문만 별도 조회하는 흐름도 확인한다. 요청 완료와 저장 완료 사이의 지연, 완료 순서가 뒤집힌 요청의 페이지 조회, 같은 URL 반복·리다이렉트, HTTP 오류·네트워크 실패·빈 본문, 바이너리 양방향, 읽기·저장·크기 실패와 취소를 검사한다. 종료·페이지 닫힘 뒤 조회, DOM 상태 유지, 등록 덮어쓰기 거절과 변경된 파일 거절도 포함한다.

최신 검사와 독립 검토 결과는 README에 기록한다. 이 검증은 실제 Agent의 조사 판단, 외부 의심 사이트, 운영 네트워크 격리·전체 트래픽 확보, AWS·진행 화면 연동을 대신하지 않는다. 브라우저 명세의 기존 13개에 네트워크 요청 조회 1개를 추가했으며 record_reader는 별도 조회 Tool이다. 수집·저장 지원 파일을 Tool 개수에 더하지 않는다.

기준: [Playwright 네트워크 사건](https://playwright.dev/python/docs/network#network-events), [Request](https://playwright.dev/python/docs/api/class-request), [Response](https://playwright.dev/python/docs/api/class-response).
