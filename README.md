# LinkGuard — URL 분석 백엔드

URL의 문자열·인프라·HTTP·콘텐츠를 관찰하고, Context Builder가 판단에 필요한 근거와 한계를 구성한다. 빠른분석 모델이 판정과 이유를 작성하며, 사용자가 심층분석을 요청하면 L4가 격리된 브라우저와 조사 도구로 추가 근거를 확보한다.

프론트엔드: [url-detection-front](https://github.com/KISIA-AI-Security-Project/url-detection-front)

## 구성

```text
L0_SCANNER/          URL 문자열과 구조 관찰
L1/                  DNS·IP·ASN·등록 정보 조회
L2_SCANNER/          HTTP 헤더·TLS·인증서 분석
L3_SCANNER/          HTML·JavaScript 정적 분석
unified_scanner/     공통 수집과 분석 실행
evidence_pipeline/  raw → record → Builder → 모델 판정 → 공개 결과
web_service/        인증·소유 확인·접수·조회·SSE·별도 VirusTotal
l4-orchestrator/    Agents SDK 총괄·실행 Agent·브라우저 도구·Store·AWS 연결
deployment/         Fast·웹 서비스 패키징과 배포 도구
frontend/           공통·이전 정적 Front 어댑터 및 계약 검사 대상
tests/              백엔드 계약·회귀 검사
docs/               계층·Builder·공개 결과·운영 연결 문서
```

현재 서비스 화면의 React 소스는 별도 프론트 저장소에서 관리한다.

## 요청 흐름

```text
Front → 인증·분석 소유 확인 → Fast 접수
  → L0 / L1 / L2·L3 공통 수집 → 계층 분석
  → raw·record 저장 → Context Builder → 모델 판정
  → 공개 Fast 결과 → 조회·SSE → Front

사용자의 심층분석 요청
  → Fast 입력 버전 확인 → L4 실행 접수 → 격리 브라우저 첫 캡처
  → 총괄·실행 Agent와 도구 → Store → DynamoDB·S3
  → 심층분석 조회·SSE → Front
```

VirusTotal은 사용자가 선택하는 별도 참고 경로다. Fast 모델 판정과 L4 근거를 덮어쓰지 않는다. 수집 실패·자료 미확보·기술적 수행 성공과 URL의 의미 판단은 구분한다. L4 첫 캡처는 페이지 `load` 완료를 기다린다.

## 시작점

- [계층·record·Builder 책임 계약](docs/context-purpose-contract.md)
- [Fast 공개 결과와 Front 계약](docs/fast-result-front.md)
- [Fast 분석 실행](EVIDENCE_PIPELINE.md)
- [L4 실행과 도구](l4-orchestrator/README.md)
- [L4 인증·시작·저장·SSE 연결](l4-orchestrator/AWS_SERVICE.md)
- [웹 서비스 배포](docs/web-service-deployment.md)

## 로컬 검사

Fast 수집·분석에는 Python 3.13 이상과 각 패키지의 의존성이 필요하다. Linux의 L2 파일 형식 분석에는 libmagic이 필요하다.

```sh
python -m pip install -r requirements-evidence.txt
python -m unittest discover -s tests -p test_web_service.py
node --test tests/web-service-client.test.mjs tests/web-stream.test.mjs tests/web-deep-progress.test.mjs
```

L4는 Python 3.12 이상을 사용한다.

```sh
python -m pip install -e './l4-orchestrator[test,browser,aws]'
cd l4-orchestrator
python -m pytest tests/test_storage.py tests/test_storage_aws_io.py tests/test_sdk_runtime.py -q
```

브라우저 검사는 Playwright 브라우저 또는 설치된 Edge/Chrome을 준비해야 한다. 저장된 과거 AWS 실행 원문을 참조하는 재생 검사는 로컬 증거 폴더가 별도로 필요하며, 해당 증거를 이 저장소에 포함하지 않는다.

## 설정과 배포

모델·VirusTotal 키는 환경 변수나 AWS Secrets Manager로 제공한다. 실제 키·사용자 토큰·로그인 자료·가상환경·빌드 산출물·실행 증거는 소스에 포함하지 않는다. 배포 도구의 리소스 식별자는 기존 환경 기준이며, 다른 계정에서는 해당 환경에 맞게 설정해야 한다.

이 `main`은 현재 구현 소스다. 개별 문서의 날짜별 운영 검증과 로컬 구현 범위를 구분하며, 전체 모델 판단 품질이나 모든 배포 경로의 검증 완료를 뜻하지 않는다. 일부 문서의 `evaluation/`·`output/` 링크는 별도로 보관한 로컬 검증 기록을 가리킨다.
