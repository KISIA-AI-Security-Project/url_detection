# L3 — HTML·JavaScript 관측 계층

악성 URL 분석 파이프라인의 L3(HTML·JavaScript 관측) 계층이다. 대상 URL을 직접 제한 수집하거나 외부에서 제공된 `L3Input`을 받아, HTML 구조와 JavaScript 정적 동작 관계를 공통 Raw Observation으로 만든 뒤 `L3-H-01`~`L3-H-08`, `L3-J-01`~`L3-J-09`의 17개 Signal을 구조화된 L3 Result로 반환한다.

원칙: 관측 ≠ 판정. `detected = true`는 해당 Signal 조건이 관측됐다는 뜻이며 URL의 최종 악성 판정이 아니다. 최종 Rule·LLM 판단과 L4 Browser 검증 여부 결정은 L3 밖의 책임이다.

원칙: 미확정·실패 ≠ 미탐지. 입력 부족, 정책 미확정, 파싱 실패, 잘린 Source는 `detected = false`로 축소하지 않고 `detected = null`과 `not_applicable` 또는 `error` 상태로 보존한다.

원칙: Raw와 Signal을 구분한다. 수집·파싱 결과는 `raw.html`과 `raw.javascript`에, 명세 조건을 적용한 분석 결과는 `signals[]`에 둔다. Python API는 공통 L3 Result를 반환하고, CLI의 `--output`은 이를 Raw JSON과 Signal JSON 두 파일로 나누어 저장한다.

세부 Signal 정의와 Evidence 계약의 최종 기준은 [`docs/L3_SPEC.md`](../docs/L3_SPEC.md)다.

## 기술 스택

| 항목 | 값 |
| --- | --- |
| 언어 | Python 3.13 이상 — `pyproject.toml`의 `requires-python = ">=3.13"` |
| HTTP 수집 | `httpx 0.28.1` + `httpcore 1.0.9` — 수동 Redirect, Streaming 크기 제한, DNS/IP 고정 연결 |
| HTML 파싱 | `beautifulsoup4 4.13.5`, 코드의 Parser backend는 `lxml` |
| URL 처리 | Python `urllib.parse` — HTTP(S) 절대 URL 검증과 상대 URL 해석 |
| 도메인 단위 | `tldextract 5.3.2` — 내장 PSL snapshot 사용, IP literal은 eTLD+1로 만들지 않음 |
| JavaScript 분석 | `esprima 4.0.1` — ESTree 기반 정적 분석, 제한적 Credential taint/Source-Sink 계보 추적 |
| 저장 | 내장 저장소 없음. CLI는 표준 출력 또는 `--output`으로 Raw/Signal JSON 두 파일을 기록 |
| 테스트 | `pytest` — 현재 69개 테스트, Mock Transport/고정 Fixture 사용, 정상 테스트는 실제 네트워크 미사용 |
| 정적 검사 | Ruff, mypy 설정(`L3_SCANNER/mypy.ini`) — 개발 도구 버전은 프로젝트 의존성에 고정되어 있지 않음 |
| 환경변수 | 현재 없음 |
| 필요 네트워크 | `scan_url`: DNS와 대상 HTTP 80/HTTPS 443. `scan_content`: 네트워크 불필요 |

`lxml`, `pytest`, Ruff, mypy는 현재 `L3_SCANNER/requirements.txt`에 직접 선언되어 있지 않다. 새 배포·CI 환경에서는 런타임 의존성과 개발 의존성을 별도로 고정해야 한다.

## Signal 범위

| ID | Signal | 관측 대상 |
| --- | --- | --- |
| `L3-H-01` | Credential Form | Credential Field를 포함한 Form |
| `L3-H-02` | Credential Field | Password·Email·Username 등 정책상 인증 필드 |
| `L3-H-03` | Form Action Domain | Form Action과 현재 eTLD+1 관계. `detected` 매핑은 미확정 |
| `L3-H-04` | External POST | 외부 eTLD+1로 향하는 POST Form |
| `L3-H-05` | Brand-Domain Mismatch | 식별 Brand와 현재 Domain의 정책상 불일치 |
| `L3-H-06` | Brand Resource Mismatch | Brand Resource와 현재·공식 Domain 관계 |
| `L3-H-07` | HTML Redirect | HTML Meta Refresh |
| `L3-H-08` | Base URL Change | 외부 Domain을 가리키는 `<base href>` |
| `L3-J-01` | Dynamic Code Execution | 정책에 등록된 동적 코드 실행 호출 |
| `L3-J-02` | Obfuscation / Decode Chain | Decode에서 실행으로 연결되는 계보 |
| `L3-J-03` | Dynamic Script Injection | 동적 Script element 생성·삽입 |
| `L3-J-04` | Network Destination | JavaScript Network API 목적지 |
| `L3-J-05` | Credential Access | JavaScript의 인증 필드 값 접근 |
| `L3-J-06` | Credential Exfiltration | Credential Source→Network Sink→외부 목적지 관계 |
| `L3-J-07` | Dynamic Redirect | JavaScript 기반 페이지 이동 |
| `L3-J-08` | Anti-Bot / Headless Detection | 자동화·Browser 환경 속성 확인 |
| `L3-J-09` | Environment-Based Branching | Browser 환경값을 조건으로 한 상이한 동작 분기 |

## 실행 방법

저장소 루트에서 Python 3.13 이상 환경을 준비하고 editable package로 설치한다.

```bash
python -m pip install -e .
```

현재 HTML Parser가 `lxml` backend를 명시하므로 새 환경에서 별도로 설치되어 있지 않다면 함께 설치해야 한다.

```bash
python -m pip install lxml
```

기본 URL 스캔은 페이지 HTML과 Inline JavaScript를 분석한다. 외부 `<script src>` URL은 Raw에 남지만 Source는 가져오지 않는다.

```bash
python -m L3_SCANNER.main https://example.com
```

외부 JavaScript Source만 제한 수집하도록 켤 수 있다. 탐지 정책은 별도이므로 이 옵션만으로 Open Detection Policy가 확정되지는 않는다.

```bash
python -m L3_SCANNER.main \
  --fetch-external-scripts \
  https://example.com
```

AWS smoke test용 임시 정책과 외부 JavaScript 제한 수집을 함께 활성화하고 결과를 파일로 저장하려면 다음과 같이 실행한다.

```bash
python -m L3_SCANNER.main \
  --all \
  --output results/l3.json \
  https://example.com
```

위 명령은 `results/l3_raw.json`과 `results/l3_signals.json`을 생성한다. 두
파일에는 동일한 `schema_version`, `layer`, `target`, `scan`, `errors`가 포함되어
같은 Scan의 결과임을 추적할 수 있다.

`--all`이 사용하는 `aws-smoke-v1`은 Parser·Analyzer 경로 확인용 임시 정책이다. 운영 악성/정상 판정 정책이 아니며 현재 테스트 대상 브랜드 값도 포함하므로 운영에 그대로 사용하지 않는다.

전체 검증:

```bash
python -m pytest L3_SCANNER/tests
```

영역별로 하나만 실행하려면:

```bash
python -m pytest L3_SCANNER/tests/test_html_parser.py
python -m pytest L3_SCANNER/tests/test_html_signals.py
python -m pytest L3_SCANNER/tests/test_javascript_parser.py
python -m pytest L3_SCANNER/tests/test_javascript_signals.py
python -m pytest L3_SCANNER/tests/test_l3_scanner.py
```

정적 검사:

```bash
python -m ruff check L3_SCANNER
python -m ruff format --check L3_SCANNER
cd L3_SCANNER && python -m mypy --config-file mypy.ini .
```

## 사용법 — 다른 계층 연동 인터페이스

L3는 L2 Result를 직접 받지 않는다. L2 또는 다른 Upstream 결과는 Adapter에서 다음 공통 `L3Input`으로 변환한 뒤 `scan_content`에 전달한다.

```text
original_url
document_url
html.content
html.content_type
html.encoding
html.truncated
scripts[]
collection_errors[]
```

대상 URL을 L3가 직접 수집할 때:

```python
from L3_SCANNER import scan_url

result = scan_url("https://example.com")
```

수집된 콘텐츠를 네트워크 접근 없이 분석할 때:

```python
from L3_SCANNER import scan_content

result = scan_content(
    {
        "original_url": "https://example.com/start",
        "document_url": "https://example.com/final",
        "html": {
            "content": "<html><script>const value = 1;</script></html>",
            "content_type": "text/html",
            "encoding": "utf-8",
            "truncated": False,
        },
        "scripts": [],
        "collection_errors": [],
    }
)
```

정책과 런타임 제한을 명시적으로 주입할 때:

```python
from L3_SCANNER import L3Scanner
from L3_SCANNER.policies import DetectionPolicy, RuntimeConfig

scanner = L3Scanner(
    policy=DetectionPolicy(),
    runtime=RuntimeConfig(
        request_timeout_seconds=10.0,
        max_redirects=5,
        max_html_bytes=2_000_000,
        max_script_bytes=1_000_000,
        max_external_scripts=20,
        fetch_external_scripts=False,
        max_javascript_events=10_000,
    ),
)
result = scanner.scan_url("https://example.com")
```

호출 결과는 저장하지 않는 Python `dict`다. 호출자가 저장·전달·보존 정책을 담당한다.

## 결과 계약

```text
schema_version     # 현재 "1.0"
layer              # "L3"
target
  original_url
  document_url
  etld1
scan
  status           # completed | failed
  started_at
  finished_at
raw
  html
  javascript
signals[]          # 항상 명세 순서의 HTML 8개 + JavaScript 9개
errors[]
```

공통 Signal 구조:

```text
id
scanner            # html | javascript
name
status             # evaluated | not_applicable | error
detected           # true | false | null
evidence
error
```

`raw.javascript`의 이벤트에는 `script_id`, `event_id`/`node_id`, `origin = "static"` 등 가능한 provenance를 남긴다. 정적 API 참조는 호출 이벤트로 조작하지 않으며 실제 Runtime Trace로 표시하지 않는다.

L3 Result에는 `malicious`, `benign`, `final_verdict`, `final_risk_score`를 넣지 않는다.

## 배포 안내 — 현재 상태

| 항목 | 현재 값 |
| --- | --- |
| 배포 형태 | Python package와 CLI |
| CLI 진입점 | `python -m L3_SCANNER.main <url>` |
| Python 진입점 | `L3_SCANNER.scan_url`, `L3_SCANNER.scan_content`, `L3_SCANNER.L3Scanner` |
| Lambda Handler | 없음 |
| Step Functions event 계약 | 없음. `job_id`·`attempt_id`도 현재 L3Input/L3 Result에 없음 |
| 런타임 | Python 3.13 이상 |
| 환경변수 | 없음 |
| 영속 저장 | 없음. S3/local records 모듈 없음 |
| 출력 | CLI 표준 출력 또는 `--output` JSON, Python API는 `dict` 반환 |
| 아웃바운드 | URL 직접 수집 시 DNS, HTTP 80, HTTPS 443 |
| AWS 권한 | 현재 코드에는 AWS SDK 호출이 없어 IAM 권한 불필요 |

Lambda·Step Functions·S3 통합이 필요하면 별도 Adapter/Handler와 저장 계약을 먼저 정의해야 한다. 이때 `L3Input`과 L3 Result를 유지하고, 저장·장부 갱신 책임을 Analyzer에 넣지 않는다.

## 구조

```text
L3_SCANNER/
├── main.py                     # CLI: URL 한 건 → 표준 출력 또는 --output JSON
├── l3_scanner.py               # Orchestrator: scan_url + scan_content + 결과 조립
├── requirements.txt            # Runtime Python 의존성
├── mypy.ini                    # Python 3.13 기준 type-check 설정
│
├── collectors/
│   ├── http_client.py          # SSRF 방어, Redirect 재검증, IP 고정, 제한 GET
│   ├── page_collector.py       # HTML 수집 → L3Input
│   └── javascript_collector.py # 명시적으로 켠 외부 Script의 제한 수집
│
├── models/
│   ├── input.py                # HTMLInput, ScriptInput, L3Input
│   ├── raw.py                  # HTML/JavaScript 공통 Raw factory
│   └── signal.py               # 공통 Signal Result와 상태 불변식
│
├── parsers/
│   ├── html_parser.py          # HTML 한 번 파싱 후 공통 Raw 조립
│   ├── html/
│   │   ├── document.py         # 문서 title/text/size/hash/완전성
│   │   ├── forms.py            # Form·Input·Button 관계와 안정 ID
│   │   ├── navigation.py       # base href·meta refresh
│   │   ├── resources.py        # image·favicon·Open Graph·script URL
│   │   └── common.py           # HTML Builder 공통 ID 도우미
│   ├── javascript_parser.py    # Script별 ESTree 정적 분석 공개 진입점
│   └── javascript/
│       ├── ast.py              # esprima 파싱·AST 순회
│       ├── analyzer.py         # 정적 Analyzer Mixin 조합
│       ├── base.py             # 상태·provenance·이벤트 ID
│       ├── expressions.py      # 표현식 평가·Credential taint 전파
│       ├── statements.py       # 문장·제어 흐름 순회
│       ├── observations.py     # Network·Injection·환경 분기 Raw 생성
│       ├── models.py           # 내부 Eval/Taint/Element 모델
│       ├── metadata.py         # Script·Credential Field 메타데이터
│       └── limits.py           # JavaScript 전체 관측 이벤트 상한
│
├── analyzers/
│   ├── html/
│   │   ├── credential_form.py             # L3-H-01
│   │   ├── credential_field.py            # L3-H-02
│   │   ├── form_action_domain.py          # L3-H-03
│   │   ├── external_post.py               # L3-H-04
│   │   ├── brand_domain_mismatch.py       # L3-H-05
│   │   ├── brand_resource_mismatch.py     # L3-H-06
│   │   ├── html_redirect.py               # L3-H-07
│   │   ├── base_url_change.py             # L3-H-08
│   │   └── runner.py                      # H-01~08 격리 실행
│   └── javascript/
│       ├── dynamic_code_execution.py      # L3-J-01
│       ├── obfuscation_decode_chain.py    # L3-J-02
│       ├── dynamic_script_injection.py    # L3-J-03
│       ├── network_destination.py         # L3-J-04
│       ├── credential_access.py           # L3-J-05
│       ├── credential_exfiltration.py     # L3-J-06
│       ├── dynamic_redirect.py            # L3-J-07
│       ├── anti_bot_headless_detection.py # L3-J-08
│       ├── environment_based_branching.py # L3-J-09
│       └── runner.py                      # J-01~09 격리 실행
│
├── policies/
│   ├── detection.py            # Open Detection Policy의 명시적 주입 계약
│   ├── runtime.py              # 수집·분석 자원 상한
│   └── experimental.py         # aws-smoke-v1 임시 정책, 운영 사용 금지
│
├── utils/
│   ├── url.py                  # HTTP(S) 해석과 PSL 기반 eTLD+1
│   └── hashing.py              # SHA-256
│
└── tests/
    ├── test_models_and_url.py
    ├── test_http_client.py
    ├── test_page_collector.py
    ├── test_javascript_collector.py
    ├── test_html_parser.py
    ├── test_javascript_parser.py
    ├── test_html_signals.py
    ├── test_javascript_signals.py
    ├── test_l3_scanner.py
    └── test_experimental_policy.py
```

## 안전장치·출력 규칙

| 항목 | 현재 값 | 목적 |
| --- | --- | --- |
| 허용 Scheme | 절대 HTTP(S)만 | 파일·로컬 Scheme 접근 차단 |
| URL userinfo | 금지 | 호스트 해석 혼동 방지 |
| SSRF 주소 검사 | DNS 응답 전체가 public global address일 때만 허용 | Loopback·private·link-local·shared·multicast 등 차단 |
| DNS rebinding 방어 | 검증한 IP를 실제 TCP 연결에 고정 | 검증 뒤 다른 주소로 연결되는 우회 차단 |
| Redirect | 최대 5회, 매 Location을 요청 전에 재검증 | Redirect 기반 SSRF·무한 이동 차단 |
| 환경 Proxy | 사용 안 함(`trust_env=False`) | 호스트 환경 의존·우회 방지 |
| 요청 제한 | 요청당 10초 | 장시간 연결 방지 |
| HTML 상한 | 2,000,000 bytes | 무제한 응답·메모리 사용 방지 |
| Script 상한 | Script당 1,000,000 bytes | 과대 JavaScript 분석 방지 |
| 외부 Script 수 | 최대 20개, 기본 수집 꺼짐 | 명시하지 않은 추가 I/O 방지 |
| JavaScript 이벤트 | 전체 10,000개 | 정적 분석 결과·메모리 상한 |
| JavaScript 실행 | 실행하지 않음, ESTree 정적 분석만 | OS·파일·실제 Network·Browser 부작용 차단 |
| Credential | 값은 저장하지 않고 type·field ID·변환·sink·목적지 관계만 저장 | 민감정보 노출 방지 |
| Analyzer 장애 | Signal별 예외 격리 | 한 Signal 실패가 나머지 16개를 중단하지 않게 함 |
| 잘린 입력 | 양성 관측은 유지, 음성은 `error`/`null`로 변경 | 부분 Source를 전체 부재로 오인하지 않음 |
| CLI 파일 저장 | 지정한 기본 이름에 `_raw`, `_signals`를 붙인 JSON 두 파일을 기록하며 기존 파일은 덮어씀 | 편의 출력일 뿐 증거 불변 저장소가 아님 |

현재 `RuntimeConfig`는 요청별 제한은 제공하지만 스캔 전체 wall-clock 예산은 제공하지 않는다. Redirect와 외부 Script 수집을 포함한 전체 실행 시간 제한은 배포 Orchestrator 또는 향후 Runtime 정책에서 별도로 정의해야 한다.

## 저장·운영 시 주의사항

- `--output results/l3.json`은 `results/l3_raw.json`과 `results/l3_signals.json`을 만들며, 같은 이름의 기존 파일은 덮어쓴다. 원본 HTTP 응답 전문을 별도 Raw Evidence로 영속 저장하는 기능은 없다.
- `job_id`/`attempt_id`, 원본 우선 저장, 조건부 쓰기, 보존 기간이 필요한 운영 증거 저장소로 사용하지 않는다.
- 외부 Script Source는 기본적으로 수집하지 않는다. Source 부재는 URL과 오류를 보존하고 JavaScript 음성 결과로 바꾸지 않는다.
- `scan_content`는 `RuntimeConfig.fetch_external_scripts=True`여도 외부 Source를 가져오지 않는다. Upstream이 `scripts[].source`를 제공해야 한다.
- `scan_url`은 HTTP error status도 수집 오류로 남긴다. 응답이 분석 가능한 HTML이면 관측 가능한 Raw와 Signal은 함께 보존할 수 있다.
- 브랜드·Credential·API 집합 등 Open Policy가 없으면 객관적 Raw는 남기되 관련 Signal을 임의 확정하지 않는다.

## 현재 미확정·미구현 항목

명세상 Open Policy는 `DetectionPolicy`로 주입하되 임의 기본값을 두지 않는다.

```text
Credential Field Classification
L3-H-03 detected semantics와 Multi-Form Evidence contract
Brand Identification / Expected Domain / Resource Matching
Dynamic Execution / Decode / Network / Redirect API set
Anti-Bot property set
Branch behavior normalization
Static reference와 Runtime execution 의미 구분 정책
L3-J-06 Source-Sink 정밀도 확장
외부 Script 운영 Fetch Policy
L4 Trigger rule / threshold
```

현재 구현하지 않은 운영 구성:

```text
제한 JavaScript instrumentation/runtime
실제 Browser 실행과 환경별 재검증
Lambda handler와 Step Functions event adapter
S3/local evidence repository
job_id / attempt_id 기반 불변 저장
원본 HTTP 응답 전문 분리 보존
스캔 전체 시간 예산
```

위 항목을 추가할 때에는 `docs/L3_SPEC.md`와 별도 운영 계약을 먼저 갱신하고, L3가 최종 악성/정상 판정이나 L4 Browser 동작을 직접 수행하도록 확장하지 않는다.
