# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 프로젝트 개요

악성 URL 분석 파이프라인의 **L2(응답, 통신 분석) 계층**. URL에 접속해 HTTP 통신, 리다이렉트, TLS 인증서를 관측하고, 통합 명세서 10장 형식의 결과 JSON을 반환한다. KISIA 팀 프로젝트의 한 계층이며 통합 명세서와 L2 기능 DB(L2-H-01~08, L2-C-01~06)가 최종 근거 문서다 — 출력 형식, 기능 범위를 바꿀 때는 명세서와 대조할 것.

## 명령어

Windows + conda 환경(`L2_scanner`). venv가 아니라 conda env의 python을 직접 호출한다:

```powershell
# 사용자 터미널에서는: conda activate L2_scanner 후 python/pip 사용
# 비대화형(스크립트, Claude Code)에서는 env의 python을 절대경로로 직접 호출:
C:\Users\ymseo\anaconda3\envs\L2_scanner\python.exe -m pip install -r requirements.txt  # 의존성 설치
C:\Users\ymseo\anaconda3\envs\L2_scanner\python.exe -m pip install -e .                 # 패키지 개발 설치 (최초 1회 — import l2_scanner를 어디서든 가능하게)
C:\Users\ymseo\anaconda3\envs\L2_scanner\python.exe -m pytest tests -q                  # 전체 테스트 (네트워크 불필요)
C:\Users\ymseo\anaconda3\envs\L2_scanner\python.exe -m pytest tests -q -k redirect      # 이름으로 필터
C:\Users\ymseo\anaconda3\envs\L2_scanner\python.exe main.py                             # 데모 (실제 네트워크 접속)
```

## 아키텍처

코드 전체가 `l2_scanner/` 패키지 하나다 (`pyproject.toml`로 설치 — 2026-08-31 패키지 구조 전환, 멘토 지시). 다른 계층은 `from l2_scanner import scan, save_evidence`만 쓰면 된다. 전체 흐름은 `l2_scanner/scanner.py`의 `scan(url)` 한 함수로 요약된다:

```
scan(url)
  → HTTP Collector (접속 1회: 리다이렉트 hop·헤더·바디)
  → Certificate Collector (TLS handshake 1회 — HTTPS 대상 있을 때만)
  → CT Collector (내장 SCT 우선, 없으면 crt.sh 폴백)
  → Analyzer 14종이 Raw Data를 공유해 Signal 생성 (재접속 없음)
  → 명세서 10장 형식 JSON 조립
```

결과 저장은 `scan()` 밖의 별도 기능이다 — `l2_scanner/storage.py`의 `save_evidence(result, job_id, attempt_id)`가 결과 dict를 **Raw Evidence 3종**(`raw/{job}/{attempt}/l2/{http,tls,ct}.json`)과 **Analysis Record**(`records/{job}/{attempt}/l2.json`)로 분리 저장한다(2026-08-31 주간회의 결정, L1 `records.py`와 같은 구조). Raw 먼저 쓰고 Record는 마지막(실행 성립의 도장), 원자적 쓰기, 같은 경로 재저장은 FileExistsError로 거부, 실패 시 예외 전파. 경로·순서의 단일 출처는 `files_to_write()`이고 S3판은 `storage_s3.py`(boto3, 배포 전용)가 같은 목록을 소비한다. 분석과 데이터화의 분리(아키텍처 V2 4장)에 따라 scan()에 저장 로직을 넣지 않으며, scan() 반환 dict는 raw를 포함한 통짜 그대로다 — 분리는 저장 계층의 일. job_id/attempt_id는 경로에만 쓰고 JSON 내용에는 넣지 않는다(스키마 팀 확정 대기).

**Collector와 Analyzer의 역할 분리가 핵심 설계다:**
- **Collector**(`l2_scanner/collectors/`)만 네트워크에 접속한다. 접속은 종류별 1회, 결과는 Raw Data dict.
- **Analyzer**(`l2_scanner/analyzers/header/`, `l2_scanner/analyzers/certificate/`)는 Raw Data만 읽는 순수 로직 — 네트워크 접속 금지. 새 Analyzer가 네트워크가 필요해 보이면 먼저 Collector에 수집을 추가하는 게 맞는지 검토할 것.
- 예외: `ct_first_seen`(L2-C-06)만 CT Raw Data를 읽으므로 `CERTIFICATE_ANALYZERS` 목록에 없고 `scan()`에서 따로 호출된다.

**Analyzer 계약** — 모든 Analyzer는 모듈 상단에 `SIGNAL = {"id", "scanner", "name"}` 상수를 노출하고, `analyze(raw: dict) -> dict` 하나로 다음 형식의 Signal을 반환한다:

```python
SIGNAL = {"id": "L2-H-03", "scanner": "header", "name": "redirect_to_ip"}
# analyze() 반환: {**SIGNAL, "detected": True | False | None, "evidence": {...}}
```

- `detected`는 3값: `True`(관측) / `False`(검사했고 미관측) / `None`(재료가 없어 검사 불가). 검사를 못 한 것을 `False`로 적지 않는다.
- `SIGNAL` 상수는 Analyzer가 예외로 죽었을 때 `scanner._run_analyzer`가 대체 Signal(detected null)을 만드는 뼈대이므로 생략 불가.

새 Analyzer 추가 시 `l2_scanner/scanner.py`의 `HEADER_ANALYZERS`/`CERTIFICATE_ANALYZERS` 목록에 **기능 번호 순서대로** 등록한다 (목록 순서 = 결과 JSON의 signals[] 순서). Analyzer는 `_run_analyzer`로 격리 실행된다 — 하나가 예외를 내도 스캔 전체가 죽지 않고 해당 기능만 null Signal + errors[] 기록으로 대체된다.

## 프로젝트 원칙 (명세서 합의 사항)

- **관측 ≠ 판정**: `detected`는 패턴 관측 여부일 뿐, 악성 판정은 상위 Rule Engine/LLM의 몫. Analyzer에 점수·판정 로직을 넣지 않는다.
- **"확인 안 됨" ≠ "없음"**: 확인하지 못한 값은 `False`/`0`이 아니라 `null`(None)로 기록한다. `detected`도 마찬가지 — 검사 자체가 불가하면 `null` (예: HTTPS 대상이 없으면 인증서 Signal 6종은 `detected: null`).
- **검증 실패해도 관측은 보존**: Certificate Collector는 체인 검증 실패 시 검증 OFF로 재접속해 인증서 자체는 수집한다 — 자체 서명·만료 인증서가 곧 분석 대상이기 때문.
- 바뀔 수 있는 상수는 환경변수가 아니라 **`l2_scanner/config/` 패키지에서 성격별로** 관리한다 — `config/tuning.py`(타임아웃·상한 등 운영 조정값), `config/knowledge.py`(위험 확장자·단축 도메인 명단 등 지식 데이터). 프로토콜 의미론(REDIRECT_CODES 등)과 Analyzer의 SIGNAL 상수는 조정 대상이 아니므로 각 모듈에 남긴다.
- 배포 환경은 **Linux 기준** (2026-08-27 팀 협의). requirements.txt의 win32 마커 줄은 로컬 개발(Windows) 편의용일 뿐이다.

## 코드 컨벤션

- 주석·docstring은 한국어. 각 Analyzer 모듈은 상단 docstring에 `[목적]/[입력]/[출력]`과 설계 근거(왜 이 범위인지, 계층 간 역할 분리)를 기록한다 — 새 모듈도 이 형식을 따를 것.
- 테스트는 가짜 Raw Data dict를 직접 만들어 `analyze()`에 주입한다 — 네트워크·mock 서버 없음. 기존 테스트 파일(`tests/test_header_analyzers.py` 등)의 패턴을 따를 것.
- 설계 배경·리뷰 Q&A는 `docs/DESIGN_NOTES.md`, 기능별 상세는 `docs/HEADER_SCANNER.md`·`docs/CERTIFICATE_SCANNER.md`, 남은 작업은 `docs/REMAINING_WORK.md`에 있다. 설계 결정을 바꾸면 해당 문서도 갱신한다.

## 미확정 사항 (팀 협의 대기 — 임의로 채우지 말 것)

- `job_id`·`attempt_id` 등 시스템 공통 식별자 (Evidence 스키마 팀 확정 대기)
- `scan.status` 세분화 (PARTIAL/BLOCKED 등 상태 Enum 팀 확정 대기)
- User-Agent 최종 값, CT 외부 API 사용 여부
