# L2 Scanner

악성 URL 분석 파이프라인의 L2(응답·통신 분석) 계층.
대상 URL에 접속해 **HTTP 통신과 리다이렉트 여정을 관측**하고, 수집한 Raw Data를 여러 Analyzer가 공유해 Signal을 생성한다.

- 근거 문서: 통합 명세서, L2 기능 DB (L2-H-01 ~ L2-H-08, L2-C-01 ~ L2-C-06)
- 원칙: **관측 ≠ 판정** (`detected`는 패턴 관측 여부, 악성 판정은 Rule Engine/LLM의 몫), **"확인 안 됨" ≠ "없음"** (unknown은 null), **접속은 1회, 분석은 공유**

## 기술 스택

| 항목 | 값 |
|---|---|
| 언어 | Python 3.13 |
| HTTP 클라이언트 | httpx 0.28.1 |
| TLS/인증서 | ssl (표준, handshake·체인 검증), cryptography 50.0.0 (X.509 파싱) |
| 파일 유형 판독 | python-magic-bin 0.4.14 (magic bytes) |
| URL 파싱 | urllib.parse (표준), tldextract 5.3.2 (eTLD+1) |
| 테스트 | pytest 9.1.1 |
| 외부 API | 없음 (CT 조회는 담당 계층 협의 후 추가 예정) |
| 환경변수 | 없음 (조정값은 각 Collector·Analyzer 상단 상수) |
| 필요 권한 | 대상 URL로의 아웃바운드 HTTP/HTTPS (TLS 443 포함) |

## 실행 방법

```powershell
# 가상환경 준비
python -m venv venv
.\venv\Scripts\pip install -r requirements.txt

# 데모 실행 (테스트 URL 목록을 스캔해 결과 JSON 출력)
.\venv\Scripts\python main.py

# 단위 테스트 (네트워크 불필요)
.\venv\Scripts\python -m pytest tests -q
```

코드에서 사용:

```python
from l2_scanner import scan
result = scan("https://example.com")   
```

## 구조

```
l2_scanner.py            # 진입점: HTTP+TLS 수집 각 1회 → Analyzer 14종 실행 → 명세서 10장 형식 결과 조립
main.py                  # 로컬 데모 (테스트 URL 목록 — badssl 인증서 이상 케이스 포함)
collectors/
  http_collector.py         # HTTP Collector — 리다이렉트 hop 추적, 헤더·바디 수집
  certificate_collector.py  # Certificate Collector — TLS handshake, 인증서·체인 수집·파싱
  ct_collector.py           # CT Collector — CT 최초 관측 시각 (내장 SCT 우선, crt.sh 폴백)
analyzers/header/        # Header Analyzer (자체 HTTP 요청 없음, Raw Data 재사용)
  redirect_chain.py          # L2-H-01 리다이렉션 체인
  redirect_domain_change.py  # L2-H-02 리다이렉트 도메인 변경 (eTLD+1)
  redirect_to_ip.py          # L2-H-03 IP 주소 리다이렉트
  url_shortener.py           # L2-H-04 단축 URL 사용
  content_type_mismatch.py   # L2-H-05 Content-Type 불일치
  dangerous_file_download.py # L2-H-06 위험 파일 다운로드
  forced_download.py         # L2-H-07 강제 다운로드
  http_refresh.py            # L2-H-08 HTTP Refresh
analyzers/certificate/   # Certificate Analyzer (TLS Raw Data 재사용)
  certificate_age.py         # L2-C-01 인증서 발급 기간
  certificate_validity.py    # L2-C-02 인증서 유효성
  hostname_match.py          # L2-C-03 도메인-인증서 일치
  self_signed.py             # L2-C-04 자체 서명 인증서
  certificate_chain.py       # L2-C-05 인증서 체인 신뢰성
  ct_first_seen.py           # L2-C-06 CT 최초 관측 (CT Raw Data → fresh 계산)
utils/
  http_parsing.py        # 공용 파싱 (Content-Disposition·RFC 5987, MIME, eTLD+1, URL 파일명)
tests/                   # 단위 테스트 102건 (가짜 Raw Data 주입 — 네트워크 없음)
```

## Collector 안전장치 (상수, `collectors/http_collector.py`)

| 상수 | 기본값 | 목적 |
|---|---|---|
| `MAX_REDIRECT_HOPS` | 15 | 무한 리다이렉트 루프 방지 (초과 hop은 관측만 기록, 접속 안 함) |
| `HTTP_TIMEOUT_SECONDS` | 10.0 | 무응답 서버 대비 |
| `MAX_BODY_BYTES` | 5MB | 초대형 응답의 메모리 고갈 방지 (잘리면 `response_body.truncated=true`, sha256은 null) |
| `USER_AGENT` | Chrome UA | 봇 클로킹으로 인한 관측 왜곡 방지 (최종 값은 팀 협의 대상) |
| SSRF 게이트 | — | 내부망·예약 주소(사설 IP, 169.254.169.254 등)로의 리다이렉트는 접속하지 않고 `errors[]`에 정책 차단으로 기록 |

## Certificate Collector 동작 방식

- **2단계 handshake**: 1차는 체인 검증 ON(OS 신뢰 저장소) → 실패하면 검증 OFF로 재접속해 인증서 자체는 수집. 자체 서명·만료 인증서야말로 분석 대상이므로 "검증 실패해도 관측은 보존"한다. 실패 사유는 `chain_error`에 원문 기록.
- **호스트명 검사 분리**: handshake의 check_hostname은 끄고, 호스트명 일치는 L2-C-03 Analyzer가 SAN을 직접 대조 — 체인 신뢰성(C-05)과 호스트명 일치(C-03)를 독립 Signal로 관측.
- **대상 선정**: 최종 도착 URL이 https면 그 호스트, 아니면 원본 URL이 https일 때 그 호스트. 둘 다 아니면 인증서 신호는 unknown(null).

