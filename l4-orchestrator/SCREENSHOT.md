# capture_screenshot — 한 번 촬영한 PNG를 SDK 이미지 입력으로 전달

실행 Agent가 호출하면 `촬영 → 로컬 PNG 저장 → 원본 반환 기록 → 같은 PNG를 다음 모델 입력에 첨부`한다. 파일 읽기와 이미지 변환은 연결 코드가 처리하며 추가 Tool 호출이나 재촬영을 요구하지 않는다.

## 책임

| 파일 | 역할 |
|---|---|
| `tools/capture_screenshot.py` | 지정된 Page를 한 번 촬영하고 호출자가 제공한 저장 함수를 사용 |
| `screenshot_storage.py` | 지정 폴더에 PNG·메타데이터 저장, 등록된 참조와 해시로 같은 PNG 읽기 |
| `sdk_files.py` | 완성 파일을 Store에 등록하고 실행 Agent에 `ToolOutputText`·`ToolOutputImage` 반환 |

## 입력과 반환

SDK에 노출되는 입력은 다음과 같다. 실제 `page_id`는 필요할 때 `context`에 함께 지정한다.

~~~json
{"target":null,"params":{"full_page":false},"context":{"state_id":null}}
~~~

런타임이 ACT와 job/task/action 추적 ID를 넣는다. 저장 폴더·모델·AWS 주소는 이 입력에서 정하지 않는다. `full_page`는 boolean이며 viewport PNG만 지원한다. `full_page=true`는 `UNSUPPORTED_CAPTURE`, 요소 target은 입력 검증 오류다.

| 성공 반환의 값 | 의미 |
|---|---|
| `artifact_ref` | 저장된 해당 이미지의 참조 |
| `sha256` | 보관 원본과 모델에 전달하는 PNG의 바이트 확인 |
| `target_type`, `captured` | `page`, `true`: 촬영과 저장이 성공함 |
| `page_id`, `captured_at` | 해당 Page와 촬영 응답을 받은 시각 |

페이지·화면 크기·스크롤 위치를 자동으로 바꾸지 않는다. `state_id=null`이면 사전 DOM 관측 없이 촬영한다. ID를 지정하면 촬영 전후 유효성을 확인하고, 촬영만으로 새 관측을 만들지 않는다.

## 실행 환경 연결

~~~python
from l4_orchestrator.tools.capture_screenshot import CaptureScreenshotTool
from l4_orchestrator.screenshot_storage import LocalScreenshotStore
from l4_orchestrator.sdk_files import FileConnections

# 호출자가 준비한 절대 경로·PageState·한도를 사용한다.
screenshots = LocalScreenshotStore(screenshot_directory)
native_tools["capture_screenshot"] = CaptureScreenshotTool(
    state, timeout_ms=capture_timeout_ms, save_png=screenshots.save_png,
)
files = FileConnections(producers=(screenshots,), screenshots=screenshots)
# native_tools를 register_native_tools에, files를 run_l4에 전달한다.
~~~

다른 파일 생산자가 있으면 같은 `FileConnections`의 `producers`에 함께 연결한다. 전체 호출 예시는 [AGENTS_SDK.md](AGENTS_SDK.md)에 있다. 이 경로의 이미지는 촬영을 요청한 실행 Agent에게 전달된다. 총괄에게 모든 Agent의 이미지를 자동 전파하는 정책은 추가하지 않는다.

## 저장과 실패 처리

기본 저장 폴더는 없다. 지정한 폴더 아래 새 UUID 디렉터리에 `image.png`, `capture.json`을 저장하고 두 파일이 준비된 후 참조를 등록한다. 기존 파일은 덮어쓰지 않는다. 이 저장 객체가 등록한 참조만 읽으며 누락·해시 불일치를 확인한다.

촬영 성공과 이미지 전달 성공은 구분한다. 이미지를 읽지 못하면 `ImageDeliveryError`가 발생하며 참조만 전달하거나 자동으로 다시 촬영하지 않는다. 촬영 자체가 실패하면 오류 본문만 전달하고 이미지 출력을 만들지 않는다. 완성 파일의 AWS 전송은 Store/publisher의 책임이다.

## 검증 범위

현재 검사는 실제 headless Edge에서 생성한 PNG를 디코딩해 크기·픽셀을 확인한다. 실제 SDK Runner의 다음 실행 Agent 모델 입력에 실린 PNG가 저장 파일과 같은 바이트인지 대조하고, Store 기록에 PNG base64가 중복 저장되지 않는지 확인한다. 모델 응답은 통제된 대역이며 실제 모델의 이미지 해석 품질을 입증하지 않는다.

파일 누락·변조·잘못된 해시, 촬영·저장 실패와 재촬영 방지 검사도 유지한다. 삭제된 옛 전용 HTTP 전송 코드의 검사는 SDK 경로로 교체했다. [초기 구현·검증 원문](../output/l4-sdk-cleanup-20261002/before/SCREENSHOT.md)과 [현재 정리 검증](../output/l4-sdk-cleanup-20261002/)을 구분해 보존한다.
