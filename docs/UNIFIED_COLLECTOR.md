# L2/L3 통합 수집기 구조

## 1. 목적

L2와 L3가 대상 URL을 각각 요청하면 서버의 클로킹, 요청 시점, User-Agent 또는
리다이렉트 상태에 따라 서로 다른 페이지를 받을 수 있다. 통합 수집기는 대상 페이지를
정확히 한 번 수집하고 동일한 불변 `PageSnapshot`을 L2와 L3에 전달하여 이러한
불일치를 방지한다.

```text
Target URL
    |
    v
url_collector.collect_url()       HTTP 페이지 수집 1회
    |
    v
PageSnapshot                      동일 본문·헤더·Redirect chain
    |----------------------|
    v                      v
L2 Page Adapter        L3 Page Adapter
    |                      |
    v                      v
L2 Raw HTTP              L3Input
    |                      |
    v                      v
L2 Analyzers         L3 Parsers/Analyzers
    |----------------------|
               |
               v
       UnifiedScanResult
```

## 2. 최종 폴더 구조

```text
url_detection/
├── url_collector/                         # 공통 네트워크 수집 계층
│   ├── __init__.py
│   ├── client.py                          # HTTP 요청, Redirect, bounded read
│   ├── models.py                          # PageSnapshot, RedirectHop
│   ├── policy.py                          # timeout, 크기, UA, Redirect 제한
│   ├── ssrf.py                            # URL/DNS/IP 검증 및 IP 고정
│   ├── errors.py                          # 구조화된 수집 오류
│   └── pyproject.toml
│
├── unified_scanner/                       # L2/L3 통합 실행 계층
│   ├── __init__.py
│   ├── scanner.py                         # 단일 수집 후 L2/L3 실행
│   ├── config.py                          # 통합 실행 설정
│   ├── models.py                          # 통합 결과 계약
│   └── pyproject.toml
│
├── L2_SCANNER/
│   └── l2_scanner/
│       ├── adapters/
│       │   └── page_snapshot.py           # PageSnapshot -> L2 Raw HTTP
│       ├── collectors/
│       │   ├── certificate_collector.py   # L2 전용 TLS 수집
│       │   └── ct_collector.py            # L2 전용 CT 수집
│       ├── analyzers/
│       └── scanner.py
│
├── L3_SCANNER/
│   ├── adapters/
│   │   ├── page_snapshot.py               # PageSnapshot -> L3Input
│   │   └── script_snapshot.py             # Script Snapshot -> ScriptInput
│   ├── analyzers/
│   ├── models/
│   ├── parsers/
│   └── l3_scanner.py
│
├── tests/
│   ├── url_collector/
│   └── unified_scanner/
│
└── pytest.ini
```

## 3. 모듈별 역할

### `url_collector`

네트워크 접속과 원본 HTTP 관측만 담당한다.

- HTTP와 HTTPS URL만 허용
- 최초 URL과 모든 Redirect 목적지에 SSRF 검사 적용
- DNS 결과를 검증하고 실제 TCP 연결을 검증된 IP로 고정
- 자동 Redirect를 사용하지 않고 각 hop을 직접 기록
- 응답 본문을 설정된 크기까지만 스트리밍 수집
- 요청 timeout과 최대 Redirect 횟수 적용
- 수집 실패를 예외로 유실하지 않고 구조화된 오류로 보존
- L2 또는 L3 모델과 분석 로직에 의존하지 않음

### `unified_scanner`

동일 페이지 보장을 책임지는 공식 통합 진입점이다.

1. 공통 Collector를 정확히 한 번 호출한다.
2. 반환된 동일 `PageSnapshot` 객체를 L2와 L3에 전달한다.
3. L2와 L3 결과를 하나의 통합 결과로 조립한다.
4. 한 계층이 실패해도 다른 계층 실행 결과를 보존한다.

HTTP 수집, Signal 분석, 최종 악성·정상 판정은 수행하지 않는다.

### `L2_SCANNER/l2_scanner/adapters`

`PageSnapshot`을 기존 L2 HTTP Raw 계약으로 변환한다.

- Redirect chain
- 최종 응답 헤더
- 본문 크기와 SHA-256
- magic bytes 기반 MIME type
- 다운로드 파일명과 확장자
- L2 형식의 수집 오류

TLS 인증서와 CT 수집은 HTTP 페이지 수집과 목적이 다르므로 L2 전용 Collector에
유지한다.

### `L3_SCANNER/adapters`

`PageSnapshot`을 기존 L3 입력 계약으로 변환한다.

- 최종 문서 URL
- HTML 본문
- Content-Type과 encoding
- 본문 잘림 상태
- 수집 오류
- 외부 JavaScript의 `ScriptInput` 메타데이터

L3는 L2 Result 또는 L2 Raw 모델에 직접 의존하지 않는다.

## 4. 공통 PageSnapshot 계약

```text
PageSnapshot
├── snapshot_id
├── collected_at
├── original_url
├── current_url
├── final_url
├── status_code
├── request_profile
│   ├── request_timeout_seconds
│   ├── max_redirects
│   ├── max_body_bytes
│   └── user_agent
├── redirect_chain[]
├── response_headers[]
├── body
├── captured_body_sha256
├── content_type
├── encoding
├── truncated
└── collection_errors[]
```

`PageSnapshot`은 frozen dataclass와 불변 값으로 구성한다. L2와 L3 어댑터는
스냅샷을 수정하지 않고 각 계층의 입력을 새로 생성한다.

통합 결과에는 민감하거나 큰 응답 본문을 다시 복제하지 않는다. 대신
`snapshot_id`, `captured_body_sha256`, 본문 크기와 수집 메타데이터를 기록한다.

## 5. 입력 방식과 호환성

기존 공개 입력 방식은 유지한다.

```python
# L2 독립 실행
from l2_scanner import scan

l2_result = scan("https://example.com")
```

```python
# L3 독립 실행 또는 제공된 콘텐츠 분석
from L3_SCANNER import scan_content, scan_url

l3_url_result = scan_url("https://example.com")
l3_content_result = scan_content(l3_input)
```

통합 실행 방식이 추가된다.

```python
from unified_scanner import scan_url

result = scan_url("https://example.com")
```

통합 모드에서 L2와 L3는 URL을 다시 수집하지 않는다. L2의 `scan_snapshot()`과
L3의 `L3Scanner.scan_snapshot()`이 전달받은 동일 스냅샷을 분석한다.

## 6. 통합 결과 구조

```text
UnifiedScanResult
├── schema_version
├── target
│   ├── original_url
│   └── final_url
├── collection
│   ├── snapshot_id
│   ├── captured_body_sha256
│   ├── request_profile
│   ├── redirect_chain[]
│   └── collection_errors[]
├── layers
│   ├── l2
│   └── l3
└── errors[]
```

통합 Scanner는 L2와 L3 결과를 묶지만 최종 `malicious`, `benign`, 위험 점수 또는
L4 실행 여부를 생성하지 않는다.

## 7. 외부 JavaScript 처리

페이지 HTML은 L2와 L3가 반드시 동일한 `PageSnapshot`을 사용한다. 외부
`<script src>` 파일은 메인 페이지와 별개의 리소스이므로 L3 설정에서 명시적으로
허용된 경우에만 공통 Collector를 추가 호출한다.

- 외부 Script 수집 기본값: 비활성화
- Script 개수, 크기, timeout과 Redirect 제한 적용
- 실제 Source를 확보하지 못하면 URL과 수집 오류 보존
- 외부 Script 수집 여부가 메인 페이지 Snapshot을 변경하지 않음

## 8. 설치

저장소 루트에서 각 패키지를 순서대로 설치한다.

```bash
python -m pip install -e ./url_collector
python -m pip install -e ./L2_SCANNER
python -m pip install -e ./L3_SCANNER
python -m pip install -e ./unified_scanner
```

## 9. 테스트와 검증

저장소 루트에서 전체 테스트를 실행한다.

```bash
python -m pytest -q
```

핵심 회귀 테스트는 다음을 확인한다.

- HTTP Collector가 통합 실행당 한 번만 호출되는지
- L2와 L3가 동일한 `PageSnapshot` 객체를 전달받는지
- Redirect chain과 최종 URL이 보존되는지
- 최초 URL 및 Redirect 목적지의 사설 IP가 차단되는지
- 설정된 본문 크기에서 수집이 중단되는지
- 한 계층의 실패가 다른 계층 실행을 막지 않는지
