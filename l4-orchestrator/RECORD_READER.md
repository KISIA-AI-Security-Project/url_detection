# 저장된 record에서 필요한 항목만 읽기

현재 SDK 연결은 [AGENTS_SDK.md](AGENTS_SDK.md)를 따른다. 아래 날짜가 붙은 초기 검증 기록은 당시 범위이며, 현재 실행 검사 결과는 [정리 검증 기록](../output/l4-sdk-cleanup-20261002/)에서 확인한다.

2026-09-28. 이번에 추가한 기능은 **저장된 record 한 건에서 지정한 항목을 읽는 Tool**이다. 실제 AWS 자료의 로컬 보관본으로 검증했다. AWS에서 새로 내려받거나, 사이트에 접속해 관찰하는 기능은 아직 연결하지 않았다.

2026-09-30 네트워크 자료 연결에서는 신뢰된 프로그램용 `register(record_ref, RecordSource)`를 추가했다. 같은 Reader에 완료된 로컬 JSON의 참조·경로·해시를 등록할 수 있으며 기존 참조를 다른 파일·해시로 바꾸는 것은 거절한다. 이 메서드는 Agent의 Tool 입력으로 노출하지 않는다. 기존 read 입력·반환·해시 검사는 유지한다. 저장은 `LocalNetworkStore`가 맡고 등록을 마친 참조만 네트워크 목록에 제공한다. 저장 범위·연결·한계는 [NETWORK_REQUESTS.md](NETWORK_REQUESTS.md)를 따른다.

## 실제 자료로 확인한 흐름

확인한 L3 record는 545,531바이트다. 짧은 문서 정보와 HTML 원문, 다른 분석 결과가 함께 들어 있다.

```text
총괄의 요청: 저장 record의 문서 정보를 읽어라
    ↓ SDK 실행 연결 → ExecutionPort
record_reader.py: 등록된 파일 확인 → 요청한 항목 선택
    ↓
문서 정보만 반환: 제목 SFE / 본문 Loading... / 정적 관찰의 한계 등
    ↓ 원문이 필요한 경우 별도 요청
같은 record에서 HTML 원문 조회 → 원문 반환
```

위 순서는 검사에서 지정했다. 실제 LLM이 추가 조회 필요성을 판단한 결과는 아니다.

## Tool에 무엇을 넣는가

```json
{
  "record_ref": "records/a5091407d4c2c2f5b8cb95a3acc6ee59/1/l3/l3.json",
  "pointer": "/observation/raw/html/document"
}
```

- `record_ref`: 읽을 record의 이름. 프로그램이 미리 등록한 파일만 읽을 수 있다. 모델이 로컬 파일 경로나 AWS 주소를 임의로 넣어 접근하는 방식은 아니다.
- `pointer`: 그 record 안에서 읽을 항목의 위치. 위 값은 `observation → raw → html → document`를 뜻한다. 빈 문자열은 전체 record를 요청한다.

원문이 필요하면 같은 `record_ref`에 `pointer`만 `/observation/raw/html/source`로 바꾼다. 항목 이름에 `/`가 있으면 `~1`, `~`가 있으면 `~0`으로 적는다. 배열은 `/items/0`처럼 위치를 지정한다.

## 무엇이 돌아오는가

| 필드 | 의미 |
|---|---|
| `status` | `ok`면 조회 성공, `error`면 아래 오류를 확인한다. |
| `record_ref`, `pointer` | 어떤 record의 어느 항목을 읽었는지 표시한다. |
| `source_sha256` | 등록 당시와 내용이 같은지 확인한 **record 파일 전체의 해시**. 확인 전 오류라면 `null`이다. |
| `data` | 요청한 항목의 JSON 값. 해석·요약·악성 여부 판단을 추가하지 않는다. |
| `error` | 성공이면 `null`, 실패이면 `code`와 `message`. |

문서 정보 조회에서는 저장된 `document` 객체를 그대로 반환한다. 따라서 제목 `SFE`, 본문 `Loading...` 외에도 **런타임 화면은 관찰하지 않았다는 `text_scope`**가 남는다. 이것을 실제 브라우저 화면에서 본 내용으로 해석하면 안 된다.

HTML 조회에서는 저장된 HTML 문자열이 돌아온다. 이 자료의 원문은 UTF-8 기준 2,881바이트이며, 문서 정보의 `sha256`과 일치한다. 이 해시는 위의 `source_sha256`과 달리 **HTML 원문만의 해시**다.

이번 검사는 반환할 `data`의 JSON 인코딩 크기를 최대 4,096바이트로 설정했다. 서비스 전체에 확정한 한도가 아니라 호출자가 정하는 설정이다. 전체 record처럼 한도를 넘는 값은 `VALUE_TOO_LARGE`로 반환하고 더 작은 항목을 요청하게 한다. 내용을 임의로 자르지는 않는다.

## 내부에서 하는 일과 저장 위치

1. 입력에 필요한 두 필드가 있는지 검사한다. 모르는 필드가 있으면 입력을 거절한다.
2. `record_ref`로 미리 등록한 파일을 찾는다. 파일 내용이 등록한 SHA-256과 다르면 조회를 중단한다.
3. **파일 전체를 내부에서 읽은 뒤**, `pointer`가 가리키는 값만 골라 반환 크기를 검사한다.
4. 값과 출처를 반환한다. 새 분석 결과나 별도 요약을 생성하지 않는다.

전체 record와 HTML 원문은 기존 보관 파일에 그대로 남는다. 이번 Tool은 이미 저장된 자료를 읽기 때문에 별도 상세 파일을 중복 생성하지 않는다.

SDK 연결은 요청·실제 Tool 입력·반환을 Store에 남긴다. 직접 Tool 작업은 실제 반환을 다음 총괄 입력에 전달하고, 실행 Agent 내부 호출은 Agent에게 반환한 뒤 작업 최종 보고와 구분해 보관한다. SDK 이력과 자료 선택 경계는 [AGENTS_SDK.md](AGENTS_SDK.md)를 따른다.

## 조회 실패와 빈 결과 구분

- 항목이 실제로 `[]`, `null`, `false`, `0`, `""`이면 성공한 조회다.
- 등록되지 않은 record: `RECORD_NOT_REGISTERED`.
- 파일을 읽을 수 없음 / 등록 후 내용 변경: `RECORD_UNAVAILABLE` / `RECORD_CHANGED`.
- 읽을 수 없는 JSON, 중복 키, 값을 바꾸지 않고 표현할 수 없는 숫자 등: `INVALID_RECORD`.
- 위치 표기 오류 / 해당 항목 없음: `INVALID_POINTER` / `VALUE_NOT_FOUND`.
- 반환 크기 초과: `VALUE_TOO_LARGE`.

기존 흐름의 `returned`는 Tool이 결과를 돌려줬다는 뜻이다. 조회 성공 여부는 그 결과의 `status`로 별도로 확인한다. 조회 실패를 ‘의심 흔적 없음’으로 바꾸지 않는다.

## 기존 뼈대에 붙이는 지점

```python
from pathlib import Path
from l4_orchestrator.tools.record_reader import RecordReader, RecordSource

ref = "records/a5091407d4c2c2f5b8cb95a3acc6ee59/1/l3/l3.json"
archive = Path("C:/Users/nickh/바탕 화면/악성 URL 탐지/docs/l4-first-investigation-20260928/sources/s3")
reader = RecordReader(
    {ref: RecordSource(archive / ref, "115d3c0033d1f6f51fcaa403412b394dd884279c6b51606d1ff21a92dbbdcfd6")},
    max_data_bytes=4096,
)

result = reader.read({"record_ref": ref, "pointer": "/observation/raw/html/document"})
native_tools["record_reader"] = reader  # register_native_tools에 전달
```

조회할 원본 파일 등록은 호출 프로그램이 담당한다. SDK는 `record_reader`의 native 입력 형식을 모델에 제공하고 같은 Reader를 연결한다. Store의 업무·작업·결과를 읽는 `read_result`와는 구분한다.

## 확인한 범위

구현은 `src/l4_orchestrator/tools/record_reader.py`, 검사는 `tests/test_record_reader.py`다. 공통 Tool 기능 검사는 유지하며 SDK 실행 연결 검사로 전환했다.

실제 보관 record와 반환값의 일치, HTML 해시, 파일 무변경, 실패와 빈 값의 구분, 크기 초과, 기존 그래프를 통한 두 번의 조회와 후속 입력을 검사했다. 전체 **35개 검사 통과**. AWS 실시간 연결, 실제 LLM의 자료 선택, Browser Tool 13개, Bash Tool의 구현 완료를 뜻하지 않는다.

독립 검토에서 일부 실수 값이 조용히 바뀌는 반례를 발견해 명시적 오류로 처리하도록 수정했다. 검토자는 수정 전 표적 검사 5개를 재현했고, 수정 후에는 해당 반례의 해결과 정상 소수 반환, 이 문서의 범위 설명을 다시 확인했다.
