# L4 현재 파일과 책임

공개 실행 함수는 `l4_orchestrator.run_l4`다. 현재 구조와 호출 방법은 [AGENTS_SDK.md](AGENTS_SDK.md)를 함께 읽는다.

## SDK 실행과 Store

| 파일 | 책임 |
|---|---|
| [__init__.py](src/l4_orchestrator/__init__.py) | 공개 `run_l4`를 필요할 때 불러옴. 저장 모듈만 쓰는 호출자는 SDK를 불러오지 않음 |
| [sdk_runtime.py](src/l4_orchestrator/sdk_runtime.py) | 총괄·실행 Agent Runner, 작업 순서·병렬 실행, Page 잠금, 마지막 판단과 종료 |
| [sdk_types.py](src/l4_orchestrator/sdk_types.py) | 총괄 반환·업무·작업·보고·실행 한도 형식 |
| [sdk_registry.py](src/l4_orchestrator/sdk_registry.py) | native Tool 등록, 모델 입력 형식, 런타임 추적 ID 주입, Store 조회 연결 |
| [sdk_tools.py](src/l4_orchestrator/sdk_tools.py) | 공통 Tool 실행, ACT 발급, 반환과 실행 오류 기록, Agent용 FunctionTool |
| [sdk_files.py](src/l4_orchestrator/sdk_files.py) | 완성 파일 등록, 네트워크 마감, 저장 PNG의 실제 모델 이미지 입력 |
| [storage/store.py](src/l4_orchestrator/storage/store.py) | 실행별 Store 객체. 배정·행동·반환·보고·파일·마감 기록 |
| [storage/aws_publisher.py](src/l4_orchestrator/storage/aws_publisher.py) | Store 기록과 파일의 AWS 전송·마감 확인 |
| [storage/aws_reader.py](src/l4_orchestrator/storage/aws_reader.py) | 저장 항목·본문·파일 조회 |

## 남겨 둔 공통 코드

| 파일 | SDK에서도 필요한 이유 |
|---|---|
| [ports.py](src/l4_orchestrator/ports.py) | native Tool의 준비·호출 접점 `ExecutionPort`와 허용 확인 결과 `Authorization` |
| [schemas.py](src/l4_orchestrator/schemas.py) | native 입력들이 상속하는 `WireModel` |
| [execution_control.py](src/l4_orchestrator/execution_control.py), [json_values.py](src/l4_orchestrator/json_values.py) | 실행 종료·저장 실패 신호와 손실 없는 JSON 처리 |
| [page_state.py](src/l4_orchestrator/page_state.py), [elements.py](src/l4_orchestrator/elements.py), [page_events.py](src/l4_orchestrator/page_events.py) | 실제 Page의 관측·요소 참조·이동과 팝업 알림 |
| [page_content.py](src/l4_orchestrator/page_content.py) | 통합 페이지 조회가 요청한 본문·링크를 같은 관측 기준으로 수집. 별도 공개 Tool이 아님 |
| [browser_pages.py](src/l4_orchestrator/browser_pages.py) | Page별 위 객체들과 native Tool 연결을 유지하고 지정 탭으로 요청 전달 |
| [network_capture.py](src/l4_orchestrator/network_capture.py), [network_storage.py](src/l4_orchestrator/network_storage.py) | 실제 네트워크 관측과 원본 저장 |
| [screenshot_storage.py](src/l4_orchestrator/screenshot_storage.py), [page_export_storage.py](src/l4_orchestrator/page_export_storage.py) | PNG·HTML의 실제 파일 저장과 완성 파일 정보 |
| [bash_process.py](src/l4_orchestrator/bash_process.py) | Bash 프로세스 실행·출력·종료 관리 |
| [tools/](src/l4_orchestrator/tools/) | 18개 Tool과 공통 입력·오류 형식. 페이지 조회 3개를 get_page_state 하나로 통합 |

## 제거한 구버전

`flow.py`, `screenshot_response.py`, `ManagerPort`, `Connections`, 옛 `Limits`·`ManagerDecision` 등은 현재 실행부에서 제거했다. 옛 그래프 규칙 전용 검사 2개 파일과 `examples/offline_demo.py`도 제거했다. 복구·이력 확인은 [정리 전 사본](../output/l4-sdk-cleanup-20261002/before/)을 사용한다.

Tool의 실제 입력·실행·반환 검사는 삭제하지 않고 SDK 경로로 옮겼다. 공통 검사 연결은 [tests/sdk_tool_checks.py](tests/sdk_tool_checks.py), 실행 코어 검사는 [test_sdk_runtime.py](tests/test_sdk_runtime.py), 실제 브라우저·Bash·파일 묶음 검사는 [test_sdk_browser.py](tests/test_sdk_browser.py)에 있다.
