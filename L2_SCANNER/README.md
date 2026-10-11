# L2 Scanner

악성 URL 분석 파이프라인의 L2(응답, 통신 분석) 계층.
대상 URL에 접속해 **HTTP 통신과 리다이렉트 여정을 관측**하고, 수집한 Raw Data를 여러 Analyzer가 공유해 Signal을 생성한다.

- 원칙: **관측 ≠ 판정** (`detected`는 패턴 관측 여부, 악성 판정은 Rule Engine/LLM의 몫), **"확인 안 됨" ≠ "없음"** (unknown은 null), **접속은 1회, 분석은 공유**

## 기술 스택

| 항목 | 값 |
|---|---|
| 언어 | Python 3.13 |
| HTTP 클라이언트 | httpx 0.28.1 |
| TLS/인증서 | ssl (표준, handshake·체인 검증), cryptography 50.0.0 (X.509 파싱) |
| 파일 유형 판독 | python-magic 0.4.27 (Linux 배포 기준, magic bytes) / python-magic-bin (Windows 개발용) |
| URL 파싱 | urllib.parse (표준), tldextract 5.3.2 (eTLD+1) |
| 테스트 | pytest 9.1.1 |
| 외부 API | crt.sh (L2-C-06 폴백 전용 — 내장 SCT 있으면 호출 안 함, 장애 시 unknown 처리) |
| 환경변수 | 없음 (조정값·지식 데이터는 `l2_scanner/config/` 패키지) |
| 필요 권한 | 대상 URL로의 아웃바운드 HTTP/HTTPS (TLS 443 포함) |

## 실행 방법

```powershell
# 패키지 설치 (개발 모드 — 의존성 포함, 어디서든 import l2_scanner 가능)
pip install -e .

# 데모 실행 (테스트 URL 목록을 스캔해 결과 JSON 출력 + records/에 저장)
python main.py

# 단위 테스트 (네트워크 불필요)
python -m pytest tests -q
```

코드에서 사용 (L3·공통 Collector·Fargate Job 등 다른 계층):

```python
from l2_scanner import scan, save_record

result = scan("https://example.com")   # 명세서 10장 형식 dict
path = save_record(result)             # Analysis Record JSON 파일 저장 (기본 records/)
```

## 구조

```
pyproject.toml           # 패키지 설치 명세 (pip install -e . - 상대경로 import 없이 어디서든 동작)
main.py                  # 로컬 데모 (테스트 URL 목록 - badssl 인증서 이상 케이스 포함)
l2_scanner/              # 패키지 본체 - 공개 진입점은 scan()·save_record() 둘뿐
  scanner.py                # 진입점: HTTP+TLS 수집 각 1회 → Analyzer 17종 실행 → 명세서 10장 형식 결과 조립
  storage.py                # Analysis Record 파일 저장 (원자적 쓰기, 덮어쓰기 금지 - S3 업로드는 AWS Job 래퍼 몫)
  collectors/
    http_collector.py         # HTTP Collector - 리다이렉트 hop 추적, 헤더, 바디 수집
    certificate_collector.py  # Certificate Collector - TLS handshake, 인증서, 체인 수집, 파싱
    ct_collector.py           # CT Collector - CT 기록 시각 (내장 SCT 우선, crt.sh 폴백)
  analyzers/header/        # Header Analyzer 8종: L2-H-01 리다이렉션 체인 / 02 도메인 변경 / 03 IP 리다이렉트
                           #   / 04 단축 URL / 05 Content-Type 불일치 / 06 위험 파일 / 07 강제 다운로드 / 08 HTTP Refresh
  analyzers/certificate/   # Certificate Analyzer 6종: L2-C-01 유효 시작 후 경과일 / 02 유효성 / 03 도메인 일치
                           #   / 04 자체 서명 / 05 체인 신뢰성 / 06 CT 기록 시각 이후 경과일
  utils/
    http_parsing.py        # 공용 파싱 (Content-Disposition, RFC 5987, MIME, eTLD+1, URL 파일명)
  config/
    tuning.py              # 운영 조정값 (타임아웃, 상한, 저장 디렉터리)
    knowledge.py           # 지식 데이터 (위험 확장자, 단축 도메인 명단)
tests/                   # 단위 테스트 130건 (가짜 Raw Data 주입 - 네트워크 없음)
```

## C01 경과일 측정 — 2026-09-28

C01은 `notBefore`(인증서 유효기간 시작 시각)와 분석 기준 시각의 차이를
`age_days`에 정수 일수로 기록한다. 30일 기준과 `fresh`/`detected` 판정을 제거했다.
`notBefore`는 실제 발급 이벤트나 도메인 등록 시각을 뜻하지 않는다.

새 C01 결과는 `result_kind: measurement`, `measurement_state: observed | unavailable`,
`evidence: {not_before, measured_at, age_days}`로 구성한다. 미래 시작 시각도
음수 경과일로 보존한다. 자료가 없거나 날짜 분석이 실패하면 `unavailable`과 원인을
남기며, 0일이나 음성 판정으로 대신하지 않는다. 다른 Analyzer의 bool 계약은 유지한다.

공통 record에는 측정값이 있는 C01을 `observed`와 비이진 `relationship_only`로
보존한다. 기존 bool/fresh 형식으로 저장된 과거 결과는 원래 의미를 유지한다.
이번 변경은 C01 생산·저장 연결이며, L23 Builder의 새로운 표시 방식은 별도 검토한다.
C06은 아래의 별도 변경을 따른다.

## C06 CT 기록 시각 이후 경과일 — 2026-09-29

C06은 수집한 CT 기록 시각과 분석 기준 시각의 차이를 정수 일수로 기록한다.
내장 SCT가 있으면 그중 가장 이른 시각을 쓰고, 없으면 기존 crt.sh 조회에서 얻은
시각을 쓴다. 30일 기준의 최근 여부 판정은 제거했다.

새 결과는 `result_kind: measurement`, `measurement_state: observed | unavailable`,
`evidence: {first_seen, age_days, measured_at, source}`로 구성하며 `fresh`/`detected`는
없다. 자료가 없거나 분석이 실패하면 실제 원인을 보존한다. 미래 시각도 음수 경과일로
남긴다. Builder는 저장된 값으로 CT 기록 시각, 검사 당시 경과일, 출처를 표시한다.
기존 저장 자료를 재계산하거나 수정하지 않는다. SCT 검증 기능을 추가하는 변경은 아니다.

## Collector 안전장치 (상수, `l2_scanner/config/tuning.py`)

| 상수 | 기본값 | 목적 |
|---|---|---|
| `MAX_REDIRECT_HOPS` | 15 | 무한 리다이렉트 루프 방지 (초과 hop은 관측만 기록, 접속 안 함) |
| `HTTP_TIMEOUT_SECONDS` | 10.0 | 무응답 서버 대비 |
| `MAX_BODY_BYTES` | 5MB | 초대형 응답의 메모리 고갈 방지 (잘리면 `response_body.truncated=true`, sha256은 null) |
| `USER_AGENT` | Chrome UA | 봇 클로킹으로 인한 관측 왜곡 방지 (최종 값은 팀 협의 대상) |
| SSRF 게이트 | — | 내부망·예약 주소(사설 IP, 169.254.169.254 등)로의 리다이렉트는 접속하지 않고 `errors[]`에 정책 차단으로 기록 |


