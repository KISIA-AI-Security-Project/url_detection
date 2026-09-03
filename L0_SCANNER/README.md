# L0 — URL 문자열 분석 계층

악성 URL 분석 파이프라인의 L0(정적 분석) 계층.
URL 문자열 하나를 받아 **WHATWG 기준으로 파싱하고, 6개 그룹 18개 항목을 판정**해
Raw Evidence와 분석 기록을 함께 돌려준다.

- 원칙: **분석 대상 서버에 접속하지 않는다** — 이것이 L1과 L0를 가르는 정의다.
  판정은 전적으로 URL 문자열과 로컬 참조 목록만으로 이루어진다. 단축 URL의
  리다이렉트도 따라가지 않고 *가능성*만 표시한다.
- 원칙: **런타임에 외부를 타지 않는다** — 참조 목록은 전부 로컬에 두고 갱신은
  배포 시점에만 한다. `tldextract`의 PSL 원격 조회도 명시적으로 끈다.
- 원칙: **판정 ≠ 악성 단정** — "해당없음"도 레코드로 남긴다. 판정을 수행했다는
  사실 자체가 증거이며, 레코드가 없으면 "검사를 안 한 것"과 "검사했는데 정상인 것"을
  사후에 구분할 수 없다.

## 기술 스택

| 항목 | 값 |
|---|---|
| 언어 | Python — 검증 환경 3.12.2, `requires-python >= 3.11` (ada-url wheel은 3.12+ 권장) |
| URL 파싱 | ada-url 4.0.0 (WHATWG URL Standard) |
| 도메인 분해 | tldextract 5.3.2 — PSL 스냅샷 내장, `suffix_list_urls=()`로 원격 조회 차단 |
| 유니코드 | `unicodedata` (표준 라이브러리) — 판본 15.0.0, Python 버전에 종속 |
| 네트워크 | **없음.** 판정 중 아웃바운드 0건 |
| 참조 목록 | `src/l0/data/` 8개 파일 — TLD 블랙리스트·무료 호스팅·브랜드·혼동 문자·확장자·단축 URL·리다이렉트 키·주입 시그니처 |
| 목록 동기화 | `scripts/sync_shorteners.py` (배치 — 이때만 네트워크 사용) |
| 검증 | 악성 URL 코퍼스 100만 건 전수 실행 (pytest 미사용) |
| 필요 권한 | 없음 (배치 실행 시에만 HTTPS 443) |

## 실행 방법

```bash
pip install -r requirements.txt
python run.py "https://g00gle.com/verify"      # URL 하나 분석
```

- 여러 개: `python run.py "url1" "url2" "url3"`
- 대화 모드: `python run.py` (빈 줄이면 종료)
- 전체 JSON: `python run.py --json "https://..."`
- 데모: `PYTHONPATH=src python -m l0.registry` (내장 예시 15건)

`run.py`가 `src/`를 import 경로에 넣어 주므로 `PYTHONPATH` 설정이 필요 없다.

## 사용법 (다른 계층 연동 인터페이스)

```python
from l0.registry import analyze

report = analyze(url_raw)
# {
#   "raw_evidence":     { stage, raw_url, parse_status, list_version, parsed, query, extracted },
#   "analysis_records": [ { "analysis_record": {...} }, ... ]   # 항상 18건
# }
```

파싱 단계만 따로 쓰거나 판정만 다시 돌릴 수도 있다.

```python
from l0.parsing import parse_url_stage
from l0.registry import run_detectors

result  = parse_url_stage(url_raw)      # 0단계 산출물 ParseResult
records = run_detectors(result)         # 판정만 (항목별 try/except 포함)
```

`parse_status`가 `SUCCESS`가 아니면 `analysis_records`는 빈 배열이다. 호스트가 IP로도
도메인으로도 성립하지 않는 문자열은 실제 브라우저도 접속을 거부하므로 후속 분석이
무의미하다. Raw Evidence만 남기고 판정을 건너뛴다.

## 판정 항목

18개 항목은 서로 결과를 참조하지 않으며 **순차 for-loop로 실행**한다. 전부 순수 CPU
연산이고 I/O가 없어 스레드는 GIL에 막히고 프로세스는 생성 비용이 판정 하나보다 크다.
URL 간 처리량은 애플리케이션 코드가 아니라 Lambda 동시성으로 확보한다.

| 그룹 | 항목 |
|---|---|
| **A** 호스트 구조 | IP 호스트 · 의심 TLD · 무료 발급 도메인 · 비표준 포트 |
| **B** 텍스트 트릭 | 콤보스쿼팅 · 타이포스쿼팅 · 퓨니코드 위장 |
| **C** 링크·파일 | 파일 다운로드 · 이중 확장자 · 단축 URL |
| **D** 파라미터 | XSS · 오픈 리다이렉트 |
| **E** 문자열 구조 | DGA 패턴 · 긴 URL · Base64 · 접속 호스트 교란 · 서브도메인 구조 |
| **F** 기타 | 비표준 프로토콜 |

각 판정 함수는 `(ParseResult) -> AnalysisRecord` 형태로 통일돼 있다. registry가 이
규약에 의존하므로, 새 판정은 해당 그룹 파일의 `GROUP_X_DETECTORS` 튜플에만 넣으면 된다.

## 구조

```
run.py                     # 실행 스크립트 — src/를 경로에 넣고 analyze 호출
requirements.txt
src/l0/
  registry.py              # 전 판정 실행 — ALL_DETECTORS(18개)·항목별 try/except·analyze()
  parsing.py               # 0단계 — WHATWG 파싱·도메인 분해·실패 사유 분류
  models.py                # AnalysisRecord·DetectionStatus·단축 함수(detected/not_applicable/failed)
  common.py                # 판정 항목명 상수 (analysis_record의 name)
  groups/
    group_a_host.py        # A: IP 호스트·의심 TLD·무료 발급 도메인·비표준 포트
    group_b_text_trick.py  # B: 콤보스쿼팅·타이포스쿼팅·퓨니코드 위장
    group_c_link_file.py   # C: 파일 다운로드·이중 확장자·단축 URL
    group_d_parameter.py   # D: XSS·오픈 리다이렉트
    group_e_string.py      # E: DGA·긴 URL·Base64·접속 호스트 교란·서브도메인 구조
    group_f_misc.py        # F: 비표준 프로토콜
  data/
    tld_lists.py           # (A-2) 피싱 빈발 TLD 블랙리스트
    free_hosting.py        # (A-3) 무료 발급 도메인 -> 카테고리
    brands.py              # (B-1, B-2) 브랜드 키워드 -> 정식 도메인 집합
    confusables.py         # (B-2, B-3) 혼동 문자 매핑
    unicode_scripts.py     # (B-3) UTS #39 Highly Restrictive 스크립트 규칙
    extensions.py          # (C-1, C-2) 확장자 -> (web_safe, role)
    shorteners.json        # (C-3) 단축 URL 도메인 — 배치가 덮어쓰는 데이터
    shorteners.py          # (C-3) 위 JSON 로더 + 버전 상수
    injection_patterns.py  # (D-1) XSS 주입 시그니처
    redirect_keys.py       # (D-2) 리다이렉트 파라미터 키
scripts/
  sync_shorteners.py       # shorteners.json 동기화 배치
```

## 저장 규칙·안전장치

| 항목 | 값 | 목적 |
|---|---|---|
| 항목별 장애 격리 | 판정 하나가 예외를 던져도 나머지 17개는 계속 진행 | 하나가 터졌다고 URL 하나의 분석을 통째로 잃지 않는다. 실패는 `status: "판정실패"` 레코드로 남는다 |
| 파싱 실패 조기 종료 | `parse_status != SUCCESS`면 판정을 돌리지 않음 | 브라우저도 접속을 거부하는 문자열이라 후속 분석이 무의미하다 |
| 쿼리 파싱 격리 | 쿼리 디코딩 실패 시 쿼리만 비우고 진행 | 쿼리를 못 읽는다고 URL을 버리면 호스트 기반 판정(A·B)까지 잃는다 |
| `list_version` 기록 | 참조 목록을 쓴 판정은 목록 버전을 함께 저장 | 목록이 갱신되면 같은 URL도 다르게 판정된다. 재현·감사에 필요하다 |
| 해당없음 레코드 | 미탐지도 반드시 레코드 생성 | "검사 안 함"과 "검사했는데 정상"을 구분한다 |
| 관찰 값 기록 | 미탐지여도 계산한 지표를 `value`에 남기는 항목이 있음 (A-2 TLD 길이, E-1 엔트로피, E-2 길이, E-5 깊이) | 임계값을 나중에 재조정할 근거가 된다 |
| 목록 로드 실패 | `shorteners.json`을 못 읽으면 빈 집합 + `list_version: "unavailable"` | import 시점에 예외를 던지면 L0 전체가 죽는다. 대신 모든 레코드에 장애가 드러난다 |

## 참조 목록 갱신 주기

| 목록 | 주기 | 출처 |
|---|---|---|
| `TLD_BLACK` | 분기 1회 | Cybercrime Information Center (Interisle) — **정규화된 phishing domain score** 기준. 단순 건수로 세면 `.com`이 1위가 되어 쓸 수 없다 |
| `FREE_HOSTING_PROVIDERS` | 반기 1회 | Mozilla PSL PRIVATE DOMAINS, MITRE ATT&CK, APWG |
| `BRAND_DOMAINS` | 반기 1회 | 국내·글로벌 사칭 빈발 브랜드 |
| `EXTENSION_RISK_MAP` | 분기 1회 | 코퍼스 관측 + MITRE ATT&CK T1204·T1566.001 |
| `shorteners.json` | **배치 자동 (주 1회, 월요일)** | PeterDaveHello/url-shorteners의 `list` − `inactive` (CC-BY-SA-4.0). 실패 시 기존 파일 유지 |
| `CONFUSABLE_MAP` / 스크립트 규칙 | 반기 1회 | Unicode UTS #39 (Security Mechanisms) |
| PSL 스냅샷 | `tldextract` 버전업 시 | 패키지 내장 |

목록을 갱신하면 **해당 파일의 버전 상수도 반드시 함께 수정한다.**

```bash
python scripts/sync_shorteners.py    # 단축 URL 목록 동기화 (네트워크 사용)
```