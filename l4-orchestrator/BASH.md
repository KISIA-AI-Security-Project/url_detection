# Bash Tool — 제공된 분석 환경에서 명령 실행

현재 SDK 연결은 [AGENTS_SDK.md](AGENTS_SDK.md)를 따른다. 아래 날짜가 붙은 초기 검증 기록은 당시 범위이며, 현재 실행 검사 결과는 [정리 검증 기록](../output/l4-sdk-cleanup-20261002/)에서 확인한다.

2026-10-01 사용자가 첫 범위를 확인하고 “그래 진행해보자”라고 승인했다. 명령 실행·출력 반환·파일 이어 사용과 기존 ExecutionPort 연결을 구현했다. 현재 Playwright Page를 Bash에서 읽는 연결은 아직 구현하지 않았다.

## 우리 프로젝트에서의 역할

실행 Agent가 확보된 자료에서 무엇을 확인할지 정하고 명령을 작성한다. 이 Tool은 그 명령을 제공된 환경에서 실행하고 실제 출력·오류를 반환한다. 실행 Agent의 조사 결정이나 총괄의 URL 판단을 대신하지 않는다.

예를 들어 네트워크 수집으로 확보한 자료를 명령에서 읽어 필요한 주소만 추출하거나 여러 파일을 비교할 수 있다. 코드가 분석 대상 파일을 미리 골라 놓거나, 이런 처리를 위해 별도 조사 Tool을 하나씩 추가하지 않는다.

- `src/l4_orchestrator/tools/bash.py`: 입력, 실행 환경 설정, 제한된 출력 수집, 비동기 호출, 반환과 `as_port()`.
- `src/l4_orchestrator/bash_process.py`: 한 호출이 시작한 프로그램들의 실행·종료 관리. 별도 Tool이 아니다.
- `tests/test_bash.py`: 실제 Bash 실행, 파일·출력·취소 검사, SDK 연결 검사.

## 실행 환경이 제공할 값

```python
from l4_orchestrator.tools.bash import BashEnvironment, BashTool

environment = BashEnvironment(
    bash_path=settings.bash_path,  # 실제 Bash 실행 파일의 절대 경로
    cwd=analysis_workdir,          # 미리 준비한 작업 폴더의 절대 경로
    env=command_environment,      # 명령에 전달할 전체 환경 변수
)
tool = BashTool(
    environment,
    max_timeout_ms=limits.command_timeout_ms,
    max_output_bytes=limits.command_output_bytes,
    cleanup_timeout_ms=limits.command_cleanup_ms,
)
port = tool.as_port()
```

이 코드는 연결 형태를 보여 준다. `settings`, `analysis_workdir`, `command_environment`, `limits`는 실행 프로그램이 제공해야 한다. 기본 Bash 경로·저장 폴더·운영 한도를 Tool이 선택하지 않는다. 모든 한도는 필수 양의 정수다.

Tool은 **Python 프로그램이 실행되는 컴퓨터의 Bash**를 실행한다. EC2에 프로그램을 배치하면 그 환경의 Bash를 사용하지만, Windows에서 호출한 Tool이 자동으로 EC2에 접속하는 기능은 없다. EC2·컨테이너·접근 권한·IAM·네트워크 정책은 제공된 환경의 책임이다. `cwd` 지정은 파일 접근 격리가 아니다.

`env`는 제공된 값만 전달한다. 호스트의 환경 변수를 자동 합치지 않으며 연결 시 복사한 값을 유지한다. 사용할 프로그램의 `PATH`와 필요한 환경 값도 호출측이 제공한다. Windows에서 필요한 시스템 환경 값도 포함해야 한다.

`max_output_bytes`는 **stdout과 stderr 각각의 보관 원바이트 한도**다. 둘을 합친 보관 원바이트는 최대 두 배이며 JSON·base64의 표현 크기 한도와는 다르다. 넘친 출력도 파이프에서 계속 읽고 버려 프로그램이 출력 때문에 멈추지 않도록 한다. 전체 출력의 별도 파일은 자동 생성하지 않는다.

`cleanup_timeout_ms`는 명령 뒤 종료·출력 수집을 확인할 별도 대기 한도다. 따라서 Tool의 실제 반환 시간은 요청한 명령 시간보다 길어질 수 있다. OS 프로세스 생성 호출 자체는 중간에 끊을 수 없으며, 늦게 생성된 프로그램도 확보한 뒤 정리한다.

## Agent가 전달하는 입력

```json
{"command": "printf '%s' '분석용 출력'", "timeout_ms": 1000}
```

숫자는 예시다. 실행 시간은 호출측 상한 이내여야 한다.

| 항목 | 의미 |
|---|---|
| `command` | 실행할 Bash 명령 또는 여러 줄 스크립트 본문. 빈 값·공백만 있는 값·NUL·잘못된 UTF-8 문자는 거절한다. |
| `timeout_ms` | 이번 명령을 기다리는 최대 시간. 필수 양의 정수이며 문자열·참/거짓을 숫자로 변환하지 않는다. |

입력으로 다른 실행 파일·환경·작업 폴더를 선택하는 필드는 없다. 모르는 필드는 거절한다. 명령 자체가 접근할 수 있는 범위는 제공된 OS 권한·격리에 달려 있다.

명령은 다른 쉘 문자열에 합치지 않고 Bash의 `-c` 인자로 전달한다. Bash 명령 안에서 필요한 인용·파이프·변수는 Bash가 처리한다. 일반 Bash 종료 규칙을 사용하며 강제 `set -e`, `pipefail`, 자동 재시도는 추가하지 않는다. 표준 입력은 비워 두므로 대화형 터미널이 아니다.

## 반환에서 확인할 값

| 항목 | 의미 |
|---|---|
| `status` | `success`, `failed`, `timeout`. 정상 종료 코드 0과 정리 확인이 있어야 success다. URL의 안전·악성 판단은 아니다. |
| `command`, `cwd` | 전달해 실행한 명령과 연결된 실제 작업 폴더. |
| `exit_code` | 정상적으로 종료를 확인한 실행의 종료 코드. 시작 실패·시간 초과·취소로 정상 명령 종료를 확인하지 못한 경우 null이다. |
| `stdout`, `stderr` | 각각의 출력에서 한도 안에 보관한 UTF-8 문자열. 줄바꿈과 원문을 임의로 정규화하지 않는다. |
| `stdout_base64`, `stderr_base64` | 보관한 원바이트가 UTF-8로 해석되지 않으면 해당 문자열은 null, 여기에는 동일 바이트의 base64가 들어간다. 한도가 문자 중간을 자른 경우도 원바이트를 유지한다. |
| `stdout_bytes`, `stderr_bytes` | 해당 파이프에서 실제 읽은 원바이트 수. 읽기 실패 시 전체 발생량으로 단정하지 않는다. |
| `stdout_truncated`, `stderr_truncated` | 출력 한도로 일부를 반환에서 생략했는지. 참이면 반환이 전체 원문이 아니다. |
| `timed_out`, `cancelled` | 시간 초과·취소 사실. 이후 정리 확인에 실패해 status가 failed가 돼도 이 사실은 유지한다. |
| `cleanup_confirmed` | 실행 프로그램과 출력 수집의 정리가 확인됐는지. 시작 전 거절 등 실행하지 않은 경우 null이다. |
| `started_at`, `finished_at`, `duration_ms` | 실행 시도와 정리의 실제 시각·소요 시간. 스레드 실행 전의 대기시간은 여기에 포함하지 않는다. |
| `error` | 오류 코드와 설명. 없으면 null이다. |

오류 코드는 `TIMEOUT_LIMIT_EXCEEDED`, `START_FAILED`, `COMMAND_FAILED`, `COMMAND_TIMEOUT`, `CLEANUP_NOT_CONFIRMED`, `OUTPUT_READ_FAILED`다. 취소된 작업의 내부 정리 결과에는 `COMMAND_CANCELLED`가 들어간다. 형식 오류는 기존 다른 Tool처럼 Pydantic 검증 오류로 전달한다.

`START_FAILED`는 Bash를 시작하지 못했거나 시작 확인을 받지 못한 경우이며 `exit_code`는 null이다. `COMMAND_FAILED`는 시작한 Bash 명령이 0이 아닌 코드로 끝난 경우다. Windows 실행기의 시작 확인을 별도 파이프로 받으므로 실제 명령의 종료 코드 1·125·126·127도 시작 실패로 오인하지 않는다. 확인 신호는 명령의 stdout/stderr에 섞이지 않는다.

호출을 취소하면 실제 명령의 정리를 기다린 뒤 `CancelledError`를 호출측에 전달한다. 반복 취소도 정리를 포기하게 하지 않는다. 취소 중 정리 확인에 실패한 경우에는 원래 반환 내용을 가진 `BashCleanupError.reply`를 전달하므로 실행부가 해당 환경을 확인할 수 있다.

## 파일은 유지하고 쉘 상태는 새로 시작한다

한 Tool 객체에 연결된 같은 폴더에서 다음 명령을 실행한다. 앞서 만든 파일은 그대로 읽을 수 있다. 다만 매번 새 Bash 프로세스가 시작하므로 앞선 명령의 `cd`, 쉘 변수, 실행 중인 터미널은 이어지지 않는다. 이전 명령의 백그라운드 프로그램도 남겨 두지 않는다.

Windows에서는 명령을 시작하기 전에 실행기 프로세스를 OS의 프로세스 묶음에 연결하고, 그 안에서 Bash와 하위 프로그램을 실행한다. POSIX에서는 한 호출마다 새 프로세스 그룹을 만들고 그 그룹을 정리한다. 이는 분석 환경 전체의 보안 격리가 아니다. POSIX에서 별도 세션으로 빠져나간 프로그램 등은 환경의 별도 격리·종료 관리가 필요하다.

## 저장·SDK·브라우저 연결

Tool의 반환을 ACT와 Store에 연결하고 실행 Agent에게 돌려주는 것은 SDK 실행부의 책임이다. `as_port()`는 공통 호출 접점이며 `register_native_tools({"bash": tool, ...})`이 native 입력 형식으로 SDK에 등록한다.

작은 출력은 반환에만 담는다. 필요한 큰 자료는 명령이 지정된 작업 폴더의 파일로 남길 수 있다. **생성한 파일의 위치를 stdout에 썼다는 사실만으로 등록된 자료 참조가 되지는 않는다.** 호출측이 그 파일을 명시적으로 확인하고 등록해야 한다. 이번 Tool은 생성 파일을 발견해 등록하는 기능이나 DynamoDB·S3 업로드를 추가하지 않는다. 잘린 출력만으로 전체 자료를 보관했다고 표시하지 않는다.

실행 Agent의 모든 명령 출력을 총괄에게 자동 전달하지 않는다. 필요한 보고·근거 선별은 Agent와 기존 연결부가 하고, 보관한 실제 반환의 추가 조회는 기존 `read_result`에 연결한다.

2026-10-02에는 `export_page`가 현재 DOM의 HTML을 파일로 확보해 Bash에 넘기는 연결을 추가했다. LocalPageExportStore의 root를 BashEnvironment.cwd와 같게 설정하고 export_page가 반환한 relative_path를 명령의 파일 인자로 사용한다. 상세 범위와 실제 연결 검사는 [EXPORT_PAGE.md](EXPORT_PAGE.md)를 따른다. Bash 명령이 현재 Page를 직접 호출하는 프로세스 간 통신은 구현하지 않았으며, 브라우저의 현재 상태를 읽는 시점은 export_page 호출 시점이다. 캡처 이미지는 기존 `capture_screenshot`의 이미지 연결을 사용한다.

## 이번 검증

최종 구현본에서 새 Bash 검사 37개와 기존 조회·실행 흐름 검사 65개를 함께 실행해 **102 passed (9.17s)**를 확인했다. 실제 설치된 Git Bash 5.2.37과 Python 3.12.14를 사용했으며 모든 분석·생성 파일은 시험용 폴더에 두었다.

- 실제 일반·오류 출력, 한글, 인용·파이프·여러 줄 명령, 정상·비정상 종료.
- 파일 이어 읽기와 `cd`·변수 미유지, 제공한 환경만 사용, 실패 시 자동 재시도 없음.
- 긴 stdout/stderr를 동시에 비우며 반환 한도 유지, UTF-8 밖의 바이트와 문자 중간에서 잘린 원바이트 보존.
- 실제 하위 프로그램의 시간 초과·단일/반복 취소·늦은 시작·정상 종료 후 백그라운드 정리.
- Windows 프로세스 묶음 연결 실패 시 Bash 미실행, 정리 또는 출력 수집 미확인 시 성공 거절. 일부 반례는 확인 실패를 의도적으로 주입한 검사다.
- 설정 후 실행 파일 삭제에 따른 시작 실패와 실제 명령의 종료 코드 1·125·126·127을 구분하고, 시작 실패 시 명령 파일이 생성되지 않음을 확인.
- 실제 보관 L3 record의 사본 → Bash의 실제 추출 → Tool 반환 → 기존 flow의 다음 시험용 총괄 입력을 동일 값으로 대조하고 원본·사본 바이트 보존을 확인.

이 결과는 Windows의 실제 명령 실행과 로컬 연결의 증거다. 이후 같은 코드와 검사를 아래 Ubuntu Linux 환경에서도 실행했다. **실제 Linux/EC2 서버의 격리·권한, 다른 배포판·컨테이너, 실제 SDK·LLM·AWS·사용자 화면과 현재 Page 연결은 아직 별도 확인 대상**이다.

새 독립 검토에서 Windows 실행기의 시작 실패를 명령 실패로 표시한 반례를 발견했다. 구현 작업이 별도 시작 확인과 회귀 검사로 수정한 뒤, 검토자가 동일 반례를 다시 실행했다. 설정 후 실행 파일을 삭제한 실제 입력에서 `START_FAILED`, `exit_code=null`, 빈 stdout/stderr, `cleanup_confirmed=true`를 확인했고 명령의 marker 파일은 생성되지 않았다.

검토자는 같은 고정본의 Bash 37개 + 별도 동시 실행·취소 3개 + 동일 삭제 반례 1개에서 **41 passed (9.43s)**를 확인했다. 실행기 생성 실패·프로세스 묶음 연결 실패·시작 보고 누락 시 제어 통로 닫힘과, 명령 출력의 제어 문자 오인 방지·실제 종료 코드 127 보존을 추가로 확인해 **4 passed (0.35s)**를 얻었다. 일부 실패는 의도적으로 주입했다. 별도 검사 원본은 `.test-tmp/bash-review-efba3e69-ff64-4e6e-bec0-90015f2fc6fb/`에 보존했다. 기존 `test_independent_review.py` 회귀 통과와 이번 새 독립 검토는 별개이며, 41개에는 위 102개와 겹치는 검사가 있다.

재검토 전후 확인한 SHA256은 다음과 같다.

| 파일 | SHA256 |
|---|---|
| `tools/bash.py` | `606A1432B924A4DF38A25D887B24A9A96513965B49FF61C81B617D9B09CDF8ED` |
| `bash_process.py` | `9997509D4012AD78EDA6B8E203E65A987981EF78DE6F460354D055ABBAFE5028` |
| `tests/test_bash.py` | `A92985F1D8F057C298824F27BBE0FB5131007C194A8DBEFF59623C3AA1585037` |

## Linux 실행 확인 — 2026-10-01

WSL2의 **Ubuntu 24.04.1 LTS / Linux 6.6.114.1 / Python 3.12.3 / GNU Bash 5.2.21**에서 서비스 코드 변경 없이 기존 검사를 실행해 **101 passed, 1 skipped (6.42s)**를 확인했다. Bash 36개와 기존 조회·실행 흐름 65개가 통과했고, Windows Job 연결 실패 검사 1개만 플랫폼 조건으로 제외됐다. 임시 Linux 가상환경에 Pydantic 2.13.5, pytest 9.1.1, LangGraph 1.2.11을 준비했고 검사 후 가상환경을 정리했다. 운영 서버에 접속하거나 시스템 Python을 변경하지 않았다.

실제 명령 출력·오류·종료 코드, 같은 폴더의 파일 이어 사용, 출력 한도, 시간 초과·단일/반복 취소 시 하위 프로그램 종료, 정상 Bash 종료 후 남은 백그라운드 자식 정리, 보관 record 추출부터 다음 시험용 총괄 입력까지의 전달을 포함한다. 독립 검토자는 아래 결과 원본과 현재 소스 해시를 대조해 검사 범위를 확인했다. 별도 Linux 재실행을 한 검토는 아니다.

- [검사 출력 원본](../docs/l4-bash-linux-verification-20261001/pytest-output.txt)
- [환경·버전·소스 SHA256](../docs/l4-bash-linux-verification-20261001/environment.json)
- [개별 검사 결과 원본](../docs/l4-bash-linux-verification-20261001/results.xml)

Linux 서버에서 연결할 때도 `BashEnvironment`와 `BashTool`의 입력 형태는 같다. 서버에 Python 3.12 이상과 실제 Bash 및 필요한 명령 프로그램이 있어야 하며, 실행부가 서버의 Bash 절대 경로·작업 폴더·환경 변수·한도를 제공한다. 이번 시험은 `/usr/bin/bash`를 사용했다. 서버의 저장 위치나 운영 제한값을 이 시험 값으로 확정한 것은 아니다.

구현 참고: [Python subprocess](https://docs.python.org/3.12/library/subprocess.html), [Python POSIX 프로세스 그룹](https://docs.python.org/3.12/library/os.html#os.killpg), [Windows 프로세스 묶음](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects). Linux 임시 시험 환경의 패키지 준비는 [pip 공식 zip 실행 파일](https://pip.pypa.io/en/stable/installation/#standalone-zip-application)을 사용했다.
