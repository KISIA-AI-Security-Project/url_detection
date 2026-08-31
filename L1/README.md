# L1 — 인프라 조회 계층

악성 URL 분석 파이프라인의 L1(인프라 관측) 계층.
URL의 호스트를 대상으로 **DNS·IP·ASN·도메인 등록 정보(RDAP)를 관측**하고,
도메인 단위 계산과 함께 기록 5개를 출구 파일 하나로 저장한다.

- 원칙: **관측 ≠ 판정** (NXDOMAIN·404 같은 부정 응답도 「응답 수신」으로 어휘 그대로 기록,
  판정은 후속 단계의 몫)
- 원칙: **분석 기록과 원본 응답을 분리해서 저장한다** (분석 기록(Analysis Record)은 응답에서
  골라낸 값들로 `records/{job_id}/{attempt_id}/l1.json`에, 원본 응답(Raw Evidence)은 서버가 보낸
  응답 전문 그대로 `raw/{job_id}/{attempt_id}/l1/`에)

## 기술 스택

| 항목 | 값 |
|---|---|
| 언어 | Python — 검증 환경 3.10.12, Lambda 런타임은 3.12+ (ada-url wheel 조건) |
| URL 파싱 | ada-url 4.0.0 (WHATWG) |
| 도메인 단위 | publicsuffixlist 1.0.2.20260821 + 보완 목록 (`src/psl_supplement.json`) |
| DNS·IP·ASN | dnspython 2.8.0 — A·AAAA·NS, Team Cymru TXT 질의 |
| RDAP | httpx 0.28.1 + IANA bootstrap 표 동봉 (`src/infra/rdap_bootstrap.json`) |
| 저장 | 로컬판 `records.py` / S3판 `records_s3.py` (boto3 — Lambda 내장, requirements에 없음) |
| 테스트 | `python -m tests.verify_<기능>` (pytest 미사용, 실제 네트워크 사용) |
| 환경변수 | `OUTPUT_BUCKET` (산출물 저장 S3 버킷 — `lambda_handler`만 읽음) |
| 필요 권한 | 아웃바운드 DNS 53·HTTPS 443, S3 put(배포 시) |

## 실행 방법

```bash
pip install -r requirements.txt
cd L1 && python3 -m tests.verify_all   # 검증 전부 실행 (약 2분, 실제 네트워크 사용)
```

- 하나만 돌리려면: `python3 -m tests.verify_<entry|domain_units|infra|failure|records>`
- 검증셋: 리포 루트 `data/verify_v1/dataset.csv`(600건). `verify_infra`는 600건 전수(약 1분)

## Lambda 배포 안내

| 항목 | 값 |
|---|---|
| Handler | `src.handler.lambda_handler` (배포 루트가 `L1/`일 때 — 코드가 `src.` 패키지) |
| event 모양 | `{ "url_raw": "...", "job_id": "...", "attempt_id": "..." }` — 반환값은 출구 JSON |
| 런타임 | Python 3.12 이상 (ada-url이 미리 빌드된 wheel을 주는 조건) |
| 환경 변수 | `OUTPUT_BUCKET` = 산출물을 저장할 S3 버킷 이름(팀 공용 저장 버킷 — L1은 그 안에 분석 기록 `records/…`와 원본 `raw/…` 키로 쓴다). Lambda 설정의 환경 변수 칸에 넣어 주면 코드가 실행 때 읽는다. 미설정이면 실행이 실패한다 |
| timeout | 90초 — L1 내부 예산이 60초라, 그보다 넉넉해야 L1이 스스로 실패를 기록하고 나온다 |
| 권한 | 지정 버킷에 `s3:PutObject` (경로 `records/*`·`raw/*`). DynamoDB 권한은 불필요 — 장부 갱신은 Step Functions 몫 |
| 아웃바운드 | DNS 53, HTTPS 443. VPC 허용목록에 `example.com`·`www.google.com/generate_204`(장애 판별용 대조 대상)와 Team Cymru(`*.asn.cymru.com`)·각 RDAP 서버로 나가는 길 |
| boto3 | Lambda 런타임 내장을 사용. 덮어쓰기 거부(`IfNoneMatch`)는 botocore 1.35.x(2024-08)+ 필요 — 런타임 동봉판 확인 |

## 구조

```
src/
  handler.py           # 진입점: run(실행 한 번의 조립 — 저장 없음) + lambda_handler(S3 저장)
  entry.py             # 입구 — URL 파싱(WHATWG)·FQDN 추출
  domain_units.py      # 도메인 단위 — 등록 단위(eTLD+1)·책임 경계
  common.py            # 기록 구조체(5칸)·상태 어휘·공용 상수
  failure.py           # 실패 처리 — Timeout 대조 판별(example.com / generate_204)·예산 60초
  records.py           # 출구 조립(l1.json)·로컬 저장 — None 칸 제거, 원본 먼저·출구 마지막
  records_s3.py        # S3판 저장 (boto3는 이 파일만)
  psl_supplement.json  # PSL 사설 구역 보완 목록
  infra/
    dns.py             # DNS A·AAAA·NS (시도당 5초 × 3회)
    ip_asn.py          # Team Cymru TXT — IP → ASN·대역·국가·조직
    rdap.py            # RDAP — 등록·만료·상태·네임서버·등록대행사
    rdap_bootstrap.json / rdap_supplement.json   # IANA 표 사본 + 보완 목록
tests/
  verify_all.py            # 다섯 검증을 순서대로 전부 실행
  verify_entry.py          # 입구 검증 — 검증셋 600건 전수 파싱
  verify_domain_units.py   # 도메인 단위 검증 — 등록 단위·책임 경계·플랫폼 목록
  verify_infra.py          # 인프라 조회 3종 검증 — 600건 전수 실조회
  verify_failure.py        # 실패 처리 검증 — 침묵 주소(192.0.2.1)로 Timeout을 만들어 판별 확인
  verify_records.py        # 실행 한 번 전체(run) 검증 — 완료·실패 경로와 저장, 산출물은 tests/out/(커밋 제외)
```

## 안전장치·저장 규칙

| 항목 | 값 | 목적 |
|---|---|---|
| 실행 시간 예산 | 60초 (`failure.TIME_BUDGET_S`) | 조회 자체 마감(15초·5초)이 안 지켜지는 상대를 만난 날의 무한 대기 차단 |
| Timeout 대조 | `example.com` / `www.google.com/generate_204` | 대상 탓·우리 쪽 장애 판별 — VPC 허용목록에 필요 |
| 덮어쓰기 거부 | 같은 `job_id/attempt_id`에 파일이 있으면 예외 | 재실행은 새 attempt_id로 — 기존 증거 보존 |
| 출구 | `records/{job_id}/{attempt_id}/l1.json` · 원본 `raw/{job_id}/{attempt_id}/l1/` | 저장 순서: 원본 먼저, 출구 마지막(성립 표지) |
