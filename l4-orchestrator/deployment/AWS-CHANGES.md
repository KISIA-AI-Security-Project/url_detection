# 첫 L4 AWS 실행에 필요한 변경

승인된 EC2 `i-0e6b3623d0a2055e7`의 `/opt/team5-l4-20261006`에 실행 파일과 결과를 둔다.
Agent·Store 컨테이너와 브라우저·Bash 조사 컨테이너를 분리한다.
조사 컨테이너에는 API 키, AWS 자격 증명, Docker 제어 소켓을 전달하지 않는다.
조사 컨테이너에서 EC2 메타데이터·호스트·사설망으로 새 연결을 만들지 못하도록 L4 전용 네트워크에 한정해 차단한다.
Chromium은 별도 사용자와 공식 Playwright seccomp 프로필로 sandbox를 켠다.

## 적용할 권한

기존 인스턴스 역할 `team5-causality-collector-20260911`에
`team5-l4-runtime-20261006` 인라인 정책을 추가한다.
정확한 내용은 `l4-instance-policy.json`이다.

| 대상 | 허용 동작 |
|---|---|
| `Team5-l4DB` | 기록 저장, META 진행 상태 갱신, 단건 조회, job별 조회 |
| 프로젝트 S3의 `l4/*` | 실행 파일·L4 결과의 저장과 조회 |
| 새 L4 Secret 1개 | 키를 메모리로 읽기 |

각 권한은 위 EC2의 인스턴스 자격 증명과 서울 리전에서만 적용된다.
빠른분석 자료 읽기는 기존 역할의 `a50914*` 범위를 사용한다.

## 키 전달

사용자가 제공한 KISIA ZIP을 AWS 계정 `998301375101`의 CloudShell로 전달한다.
Python이 ZIP 안의 `opencode (1).json`을 읽어, 키와 Gateway 주소를
서울 리전 Secrets Manager의 `team5/l4/monorouter-20261006`에 저장한다.
업로드된 ZIP은 저장 성공 후 CloudShell에서 지운다.
실행 이미지·소스·명령줄·모델 전송 기록에는 키를 넣지 않는다.

## 첫 검증

`first-request.json`의 실제 Django 분석 결과를 읽는다.
총괄과 실행 Agent 모두 `gpt-6-astra/high`로 실행한다.
총괄 최대 6차례에는 마지막 판단을 포함하며, 작업당 SDK 반복은 최대 8회,
추가 조사는 180초다. 한도에 닿으면 기존 결과로 최종 판단한다.

검증 대상은 실제 Builder 본문·전체 Judgment·최초 PNG의 첫 모델 전송,
실제 모델 및 Tool 반환, DynamoDB와 S3의 저장·조회다.
Front의 심층 시작 HTTP 연결은 이 검증 후 연결 담당 세션과 계약을 확정한다.
