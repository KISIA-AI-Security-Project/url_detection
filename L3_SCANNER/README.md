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
| 테스트 | `pytest` — 현재 96개 테스트, Mock Transport/고정 Fixture 사용, 정상 테스트는 실제 네트워크 미사용 |
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

기본 URL 스캔은 `operational-v1` 탐지 정책으로 페이지 HTML과 Inline JavaScript를 분석한다. 외부 `<script src>` URL은 Raw에 남지만 Source는 가져오지 않는다.

```bash
python -m L3_SCANNER.main https://example.com
```

외부 JavaScript Source만 제한 수집하도록 켤 수 있다. 탐지 정책은 별도이므로 이 옵션만으로 Open Detection Policy가 확정되지는 않는다.

```bash
python -m L3_SCANNER.main \
  --fetch-external-scripts \
  https://example.com
```

운영 정책과 외부 JavaScript 제한 수집을 함께 사용해 결과를 파일로 저장하려면 다음과 같이 실행한다.

```bash
python -m L3_SCANNER.main \
  --fetch-external-scripts \
  --output results/l3.json \
  https://example.com
```

위 명령은 `results/l3_raw.json`과 `results/l3_signals.json`을 생성한다. 두
파일에는 동일한 `schema_version`, `layer`, `target`, `scan`, `errors`가 포함되어
같은 Scan의 결과임을 추적할 수 있다.

기본 정책 파일은 `policies/operational.v1.json`이다. Credential Field와 공통
JavaScript API 집합은 기본 제공하지만 특정 서비스의 브랜드명이나 공식 도메인을
하드코딩하지 않는다. 운영 브랜드 정책의 단일 외부 공급원은 Wikidata이며, 별도
동기화 명령이 생성한 로컬 캐시만 Scanner에 주입한다. Analyzer는 Wikidata를 직접
호출하지 않는다.

브랜드명을 한 줄에 하나씩 기록한 파일로 캐시를 생성한다. 동명 Item, 검색 실패,
현재 `P856` 공식 웹사이트 부재 항목은 `unresolved`에 보존되며 탐지 정책에 포함되지
않는다. 운영 환경의 `--user-agent`에는 연락 가능한 정보를 포함하는 것이 좋다.

브랜드명 파일 대신 Cloudflare Radar의 ordered global top Domain을 사용할 수 있다.
Cloudflare는 후보 순위만 제공하고, 각 Domain이 Wikidata `P856`과 일치할 때만
브랜드 정책에 포함된다. API Token은 지정한 환경변수에서만 읽으며 캐시·로그·결과에
저장하지 않는다. Cloudflare가 정확한 순서를 제공하는 범위에 맞춰 N은 1~100이다.

```bash
export CLOUDFLARE_API_TOKEN="..."

python -m L3_SCANNER.brands.main \
  --cloudflare-top-domains 100 \
  --user-agent "L3-Scanner/1.0 (security@example.com)" \
  --output L3_SCANNER/brands/data/wikidata-brands.json
```

`selection.provider=cloudflare_radar`, 선정 Domain·순위, Wikidata QID와 revision이
캐시에 남아 어떤 Ranking 후보가 어떤 Wikidata 정책으로 확정됐는지 추적할 수 있다.

```bash
python -m L3_SCANNER.brands.main \
  --brand-file /path/to/brands.txt \
  --user-agent "L3-Scanner/1.0 (security@example.com)" \
  --output L3_SCANNER/brands/data/wikidata-brands.json
```

기존 캐시의 요청 브랜드 전체를 다시 조회해 주기적으로 갱신할 수 있다.

```bash
python -m L3_SCANNER.brands.main \
  --refresh-cache L3_SCANNER/brands/data/wikidata-brands.json \
  --output L3_SCANNER/brands/data/wikidata-brands.json
```

```bash
python -m L3_SCANNER.main \
  --wikidata-brand-cache L3_SCANNER/brands/data/wikidata-brands.json \
  --fetch-external-scripts \
  https://example.com
```

수동 정책 JSON의 `brands` 구조는 하위 호환을 위해 유지하지만 Wikidata 캐시와
동시에 주입할 수 없다. 이는 브랜드·공식 도메인이 다른 공급원과 조용히 혼합되는
것을 막는다. 제목 또는 `og:site_name`에서 동시에 여러 브랜드가 일치하면 브랜드를
확정하지 않는다.

```json
{
  "brands": {
    "your-brand": {
      "title_tokens": ["Your Brand"],
      "site_name_tokens": ["Your Brand"],
      "hostname_tokens": ["yourbrand", "your-brand"],
      "expected_domains": ["example.com"],
      "resource_domains": ["example-cdn.com"]
    }
  },
  "brand_resources": {
    "shared_domains": ["shared-cdn.com"]
  }
}
```

실제 파일에는 위 항목 외에도 기본 정책 파일의 `schema_version`, Credential,
JavaScript 설정이 모두 필요하다. 알 수 없는 필드, 잘못된 Domain, 빈 필수 API
목록은 Scanner가 네트워크 요청을 시작하기 전에 거부한다.

`hostname_tokens`는 URL 전체가 아니라 IDNA 정규화된 Hostname Label에만 적용한다.
Token과 Label이 같거나 `-` 경계로 구분된 경우만 일치하며 Path·Query는 검사하지
않는다. Hostname만으로 브랜드가 식별되면 `brand_identification_confidence=low`,
제목이나 `og:site_name` 근거가 있으면 `high`를 Evidence에 기록한다. L3는 가중치를
계산하지 않으며 downstream Rule/LLM이 이 값을 사용한다.

Wikidata 캐시는 현재 공식 웹사이트 속성 `P856`의 non-deprecated Statement를 읽고,
종료 시각이 지난 URL을 제외하며 preferred rank가 있으면 그것만 사용한다. H-05는
그 Domain으로 평가한다. `P856`에는 CDN·브랜드 Resource 소유 정보가 없으므로 H-06은
현재/공식 Domain 안의 Resource만 `false`로 확인하고 알 수 없는 외부 Resource는
`detected=null`로 유지한다.

## URL Feed 데이터셋 테스트

`url`, `sources`, `source_status`, `first_seen` 열을 가진 CSV 또는 단일 CSV가 든
ZIP을 입력할 수 있다. ZIP은 디스크에 풀지 않고 스트리밍하며 데이터셋의 URL을
탐지 정책이나 정답 Label로 사용하지 않는다.

네트워크 요청 없이 전체 데이터셋의 행 수, 활성 상태, HTTP(S) 적합성, 제외 사유를
확인한다.

```bash
python -m L3_SCANNER.dataset_main /path/to/dataset.zip
```

실제 악성 URL 수집은 자동으로 시작되지 않는다. `--scan`과 양수 `--limit`, 출력
디렉터리를 모두 명시해야 하며 기본적으로 활성 상태의 HTTP(S) URL만 순차 처리한다.

```bash
python -m L3_SCANNER.dataset_main /path/to/dataset.zip \
  --scan \
  --limit 10 \
  --offset 0 \
  --fetch-external-scripts \
  --output-dir results/dataset-smoke
```

각 URL은 `row-<행>-<URL 해시>_raw.json`과
`row-<행>-<URL 해시>_signals.json`으로 분리되며, `manifest.json`에 원본 행
메타데이터·처리 상태·출력 파일명이 기록된다. `--include-inactive`를 지정하지 않으면
`ACTIVE`, `online`, `yes` 상태만 포함하고 `INACTIVE`, `offline` 표시는 우선 제외한다.

데이터셋 CLI에서도 요청 시간, Redirect, HTML/Script 크기, 외부 Script 개수,
JavaScript Event 상한을 명시적으로 조정할 수 있지만 무제한 값은 허용하지 않는다.

이 URL Feed에는 정상 대조군, 브랜드 정답/공식 도메인, HTML·JavaScript Snapshot이
없으므로 False Positive 평가, `L3-H-03` 정책 확정, 브랜드 Signal 정답 생성에는 별도
Dataset/Policy가 필요하다.

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
  policy_name      # 적용한 운영 정책 버전
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
├── dataset_main.py             # URL Feed 사전 검사와 명시적 제한 배치 CLI
├── dataset.py                  # ZIP/CSV 스트리밍·필터·배치 Orchestration
├── l3_scanner.py               # Orchestrator: scan_url + scan_content + 결과 조립
├── output.py                   # Raw/Signal JSON 분리 저장 공통 도우미
├── brands/                     # 브랜드 선정·정책 데이터셋 통합 관리
│   ├── main.py                 # 브랜드 캐시 생성·갱신 CLI
│   ├── cloudflare.py           # Radar ordered top Domain 제한 수집
│   ├── wikidata.py             # P856 동기화·검증·버전형 로컬 캐시
│   └── data/                   # 생성 캐시와 선택적 브랜드명 입력
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
│   ├── operational.py          # JSON 검증과 범용 운영 정책 Builder
│   └── operational.v1.json     # 기본 operational-v1 정책 값
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
    ├── test_dataset.py
    ├── test_cloudflare_selection.py
    ├── test_operational_policy.py
    └── test_wikidata_policy.py
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
- 미등록 브랜드는 객관적 Raw를 남기되 관련 Signal을 음성으로 확정하지 않는다.

## 현재 미확정·미구현 항목

범용 Credential/API 값은 `operational-v1`에서 명시적으로 버전 관리한다. 특정 브랜드와
공식·허용 Resource Domain은 조직별 운영 정책에 주입하며 기본값을 만들지 않는다.

```text
L3-H-03 detected semantics와 Multi-Form Evidence contract
Static reference와 Runtime execution 의미 구분 정책
L3-J-06 Source-Sink 정밀도 확장
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
