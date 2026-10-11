# L4 — OpenAI Agents SDK 실행과 저장

L4의 실행 진입점은 `l4_orchestrator.run_l4`다. 총괄이 업무·작업과 다음 판단 시점을 정하고, 실행 코드가 Tool·Agent 작업을 진행하며, 하나의 `L4Store`에 기록한다. `AwsPublisher`가 같은 기록과 파일을 DynamoDB·S3로 전송한다.

**현재 상태:** SDK·18개 native Tool·Store와 AWS 시작·조회·SSE 연결을 구현했다. 2026-10-06 실제 Fast 입력으로 L4가 첫 화면을 직접 캡처하고 Astra 총괄에게 전달해, 최종 보고·파일을 DynamoDB·S3에서 다시 읽었다. 인증된 서비스의 심층분석 버튼으로 Rust 실행을 시작하고 완료 결과를 SSE로 수신했다. 실제 AWS 스트림 원문과 프론트 상세 연결도 별도 대조했다. 두 실제 사례는 총괄이 바로 종료해 실행 Agent와 추가 Tool 조사는 발생하지 않았다.

## 읽는 순서

| 문서 | 확인할 내용 |
|---|---|
| [AGENTS_SDK.md](AGENTS_SDK.md) | 설계 기준, 호출 인자, 실행·종료·오류 처리, 남은 연결 |
| [AWS_SERVICE.md](AWS_SERVICE.md) | 인증·실행 접수·DB/S3 지속 조회·SSE·프론트 상세의 책임과 구현 |
| [AWS 실행 검증](../output/l4-aws-runtime-20261006/AWS-VERIFICATION.md) | 실제 입력·모델·저장·응답과 검증하지 않은 범위 |
| [FILE-MAP.md](FILE-MAP.md) | 현재 파일별 책임과 공통 코드 |
| [VISUAL-GUIDE.md](VISUAL-GUIDE.md) | 총괄·실행 작업·Store·AWS의 흐름 |
| [BROWSER_PAGES.md](BROWSER_PAGES.md) | 열린 탭 조회와 요청별 `page_id` 지정 |
| [PAGE_QUERY.md](PAGE_QUERY.md) | 한 번의 조회에서 상태·본문·링크·요소 선택 |
| [REVIEW.md](REVIEW.md) | 검증 자료와 독립 검토 범위 |

## 실행 연결

AWS에서는 `aws_start.py`가 심층분석 요청을 접수하고 고정 SSM 문서가 `deployment/run_job.py`를 실행한다. `aws_runner.py`가 실제 Fast 자료·모델·사용자 승인 한도·격리 Tool·Store·publisher를 준비하고 첫 캡처를 포함해 `run_l4`를 호출한다. 직접 함수 호출 예시는 [AGENTS_SDK.md](AGENTS_SDK.md)에 있다.

`register_native_tools(native_tools)`는 기존 Tool 객체와 native 입력 형식으로 SDK 연결을 만든다. `ExecutionPort`, `Authorization`, `WireModel`은 공통 정의로 남아 있다. LangGraph 실행부·전용 형식·전용 검사는 현재 패키지에서 제거했다. 기존 Tool의 실제 기능 검사는 SDK 경로로 옮겼다.

## 제공되는 Tool

| 용도 | 이름 | 상세 설명 |
|---|---|---|
| 기록 조회·분석 | `record_reader`, `read_result`, `bash` | [원본 기록](RECORD_READER.md), [Store 조회](READ_RESULT.md), [Bash](BASH.md) |
| 페이지와 요소 조회 | `get_page_state` | [선택 조회](PAGE_QUERY.md), [탭·Page 연결](BROWSER_PAGES.md), [본문](PAGE_CONTENT.md) |
| 이동 | `navigate`, `go_back`, `reload` | [뒤로 가기](GO_BACK.md), [다시 읽기](RELOAD.md) |
| 입력·상호작용 | `click`, `fill`, `press_key`, `check`, `select_option` | [클릭](CLICK.md), [입력](FILL.md), [Enter](PRESS_KEY.md), [체크](CHECK.md), [선택](SELECT_OPTION.md) |
| 화면 조작·대기 | `scroll`, `hover`, `wait_for` | [스크롤](SCROLL.md), [가리키기](HOVER.md), [대기](WAIT_FOR.md) |
| 자료 확보 | `capture_screenshot`, `export_page`, `get_network_requests` | [이미지](SCREENSHOT.md), [HTML 파일](EXPORT_PAGE.md), [네트워크](NETWORK_REQUESTS.md) |

18개 Tool을 제공한다. 페이지 상태·요소·본문 조회를 `get_page_state` 하나로 통합했으며 `params.include`로 text·links·elements 중 필요한 자료만 요청한다. `get_page_state(params.scope="pages")`로 열린 탭을 확인하고 `context.page_id`로 호출할 탭을 지정한다. 생략하면 호출자가 정한 기본 탭을 사용한다. Page별 관측·요소·Tool 연결은 `BrowserPages`가 유지한다.

## 설치와 검사

`pyproject.toml`의 기본 의존성은 OpenAI Agents SDK와 Pydantic이다. `test`, `browser`, `aws` 추가 의존성은 검사·실행 환경에 맞게 선택한다. `requirements.lock.txt`는 현재 Windows 환경에서 확인한 SDK·검사·AWS 의존성 버전이고, 브라우저 버전은 `requirements-browser.lock.txt`에 있다.

~~~powershell
.venv/Scripts/python.exe -m pip install -e '.[test,browser,aws]'
$env:L4_BROWSER_CHANNEL = 'msedge'
.venv/Scripts/python.exe -m pytest tests -q -p no:cacheprovider
~~~

제한된 환경에서는 `--basetemp`로 작업 폴더 안의 새 폴더를 지정한다. 검사 중 실제 모델 API와 실제 AWS에 연결하지 않는다.

## 정리 전 기록

정리 전 소스·검사·설명은 [고정 사본](../output/l4-sdk-cleanup-20261002/before/)과 해시 목록으로 보존했다. 이전 빌드 사본도 `../output/l4-sdk-cleanup-20261002/old-build/`로 옮겼다. 각 Tool 문서의 날짜가 붙은 초기 검증 수치는 그 당시의 범위다. 최신 검증 자료는 [정리·검증 결과](../output/l4-sdk-cleanup-20261002/verification.md)에서 확인한다.
