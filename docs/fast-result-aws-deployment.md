# fast-result-1 AWS 후보 생성과 연결

기준은 [승인된 Notion 설계](https://app.notion.com/p/2ae3dea100f783c596d901663edab660)다. 이 도구는 **로컬 ZIP·ASL·설정 계약**을 만든다. Lambda·IAM·API Gateway·Step Functions를 조회하거나 변경하지 않는다. 생성한 ARN의 존재와 현재 운영 연결 여부도 확인하지 않는다.

현재 실제 서비스의 배포·연동 확인은 [서비스 배포 확인](web-service-deployment.md)에 있다. 아래 날짜별 후보 생성 기록은 당시 상태를 보존한 것이며 현재 서비스 상태를 대신하지 않는다.

## 생성하는 것

| 파일 | 사용처 |
|---|---|
| `context.zip` | 기존 `aws_runtime.handler`, `EVIDENCE_ROLE=context`, `EVIDENCE_RESULT_CONTRACT=fast-result-1` |
| `judgment.zip` | 같은 runtime handler, `EVIDENCE_ROLE=judgment`, `EVIDENCE_RESULT_CONTRACT=fast-result-1` |
| `result.zip` | `app.handler`. 기본은 app.py·최상위 fast_public.py와 기존 v2 의존성 evidence_pipeline/dns를 함께 포함 |
| `definition.json` | 입력 ASL을 변환한 직접 Judgment 후보 |
| `definition-original.json` | 입력 ASL 보존본 |
| `deployment-contract.json` | 전달한 ARN·모델 설정·환경변수·권한·API 연결 대상 |
| `manifest.json` | 입력 정의·소스·ZIP hash와 로컬 import 상태 |
| `offline-import-verification.json` | ZIP을 저장소 밖에서 추출해 import한 결과와 합성 Result 호출 결과 |

Context/Judgment ZIP에는 현재 `evidence_pipeline`의 코드·prompt와 설치된 `dnspython`의 `dns` 디렉터리를 함께 넣는다. boto3는 Lambda 환경의 SDK를 사용한다. **기본 Result도 이 의존성을 포함해 기존 작업 조회를 유지한다.** 새 계약 요청에서는 가벼운 최상위 fast_public.py를 쓰고 v2 모듈은 기존 결과를 읽을 때 import한다. 기존 S3 조회 권한도 보존해야 한다.

`--fast-only-result`를 명시하면 전용 endpoint에 사용할 app.py·fast_public.py 두 파일 패키지를 만들 수 있다. 이는 선택사항이며 기존 v2 작업까지 조회하는 API의 기본 패키지가 아니다.

이 생성기는 수집기 이미지를 새로 만들지 않는다. 입력 ASL에 명시된 L0·L1·L23 함수를 유지한다. 실제 배포 시 수집 결과가 현재 record·Builder 입력 계약과 맞는지는 해당 배포본과 같은 입력으로 확인해야 한다.

## 명령

저장소 루트 `evaluation/remediation-20260911/repo`에서 실행한다. 다음은 **로컬 후보 예시**이며 ARN·모델명·secret ID는 실제 리소스 확인 결과가 아니다. 실제 배포 준비에서는 선택한 값으로 바꾼다. API key 값은 인자로 전달하지 않는다.

```powershell
$candidateArgs = @(
  '-m', 'deployment.build_fast_result_candidate',
  '--definition', '../../remediation-20260920/integration/release-inputs/definition.json',
  '--output', '../../remediation-20261002/fast-result-implementation/aws-candidate-your-release',
  '--context-arn', 'arn:aws:lambda:ap-northeast-2:998301375101:function:team5-itg-fast-context-candidate:1',
  '--judgment-arn', 'arn:aws:lambda:ap-northeast-2:998301375101:function:team5-itg-fast-judgment-candidate:1',
  '--result-arn', 'arn:aws:lambda:ap-northeast-2:998301375101:function:team5-itg-fast-result-candidate:1',
  '--model', 'offline-package-check',
  '--base-url', 'https://example.org/model',
  '--secret-id', 'team5/fast-result/offline-reference'
)
python -X utf8 -B @candidateArgs
```

출력 디렉터리는 새 경로여야 한다. 이미 생성한 증거를 덮어쓰지 않는다. 과거 직접 호출 정의인 `../../dns-inactivity-20260916/dual-dns-failure-patch-v2/definition-v5.json`도 입력할 수 있다.

지원하는 입력은 현재 명시 Context 계약을 가진 ASL이다. ContextTask에 `job_id`, `attempt`, `url`, 네 계층의 참조와 `url_activity`가 있어야 하며 `AllocAttempt`·`MarkContext`·`MarkJudged`·`MarkFailed`는 같은 장부를 사용해야 한다. 예전 `ContextTask=Pass` 정의에는 입력을 추정해서 붙이지 않고 명시적으로 오류를 반환한다.

## ASL과 DynamoDB의 변경

1. **시작:** `AllocAttempt`는 `result_contract_version=fast-result-1`, `judgment_status=pending`을 남긴다. 이전 공개 키, context/result revision, 판정 참조와 verdict를 초기화한다. 기존 attempt 증가와 fragments 초기화는 유지한다.
2. **Context:** ContextTask와 ActivityTask에 전달한 Context ARN을 넣는다. MarkContext가 기존 final_key와 함께 공개 pending/result 키 및 context revision을 기록한다.
3. **직접 Judgment:** 기존 `QwenInit`, wait/count/polling 상태를 제거하고 JudgmentTask로 바로 연결한다. collector·접속 안전 정책·활동 상태 분기는 유지한다.
4. **accepted:** `MarkJudged`가 공개 result 키, context/result revision, Judgment 참조, `judgment_status=accepted`, 모델 verdict를 기록한다.
5. **failed/invalid:** `MarkFastResultFailed`가 공개 실패 result 키와 revision 및 상태를 기록한다. verdict와 Judgment 참조를 남기지 않고 실패 종결로 이동한다.
6. **Lambda/SFN 자체 오류:** 기존 MarkFailed로 간다. `judgment_status=failed`를 기록한다. Context가 이미 있으면 Result는 같은 사실을 유지하면서 실패 상태를 제공할 수 있다. 서비스 실패를 모델의 UNKNOWN으로 바꾸지 않는다.

Result ARN은 SFN Task가 아니다. API의 조회 Lambda 연결 대상으로 `deployment-contract.json`에 남긴다. 기존 사용자 API를 이 ARN에 연결하거나 호환 패키지로 갱신하는 작업은 이 도구가 수행하지 않는다.

## 런타임 설정

- Context/Activity Lambda: handler `evidence_pipeline.aws_runtime.handler`, 역할 `context`, 프로젝트 `OUTPUT_BUCKET`, 계약 버전, `CONTEXT_MAX_BYTES`.
- Judgment Lambda: 같은 handler, 역할 `judgment`, 계약 버전, `ANTHROPIC_BASE_URL`, `JUDGMENT_MODEL`, `LLM_SECRET_ID`, timeout/max tokens.
- Result Lambda: handler `app.handler`, `JOBS_TABLE`, `EVIDENCE_BUCKET`.

기본 후보는 provider timeout 50초, Judgment Lambda 60초, SFN Judgment Task 75초를 사용한다. `--model-timeout`, `--lambda-timeout`, `--task-timeout`으로 함께 바꿀 수 있고 provider < Lambda < Task 관계를 확인한다. 출력 예약은 기본 4,096이며 `--max-tokens`로 바꾼다. 이 숫자는 모델 성능·실제 지연 검증 결과가 아니다.

현재 Context/Activity Task는 기존 명시 Context 경로의 60초 기준을 사용하며 생성 설정의 Lambda 제한은 55초다. VPC·역할·네트워크 경로·로그·SDK 버전은 입력된 실제 배포 환경에서 확인해야 한다. 저장 JSON 전체를 SFN 상태에 넣지 않고 job/attempt와 S3 참조를 전달한다.

## 공개 결과와 심층분석

Result는 장부의 `result_contract_version=fast-result-1`을 확인하고 현재 attempt의 공개 artifact를 반환한다. 브라우저에는 공개 사실·판정·이유와 해당 버전만 전달한다. 원본·S3 키·`decision_notes`·범위/미확인 목록은 포함하지 않는다.

기존 `MarkSafetyBlocked`는 Context 생성 전에 `TARGET_BLOCKED`·`not_requested`로 종료한다. 이때 공개 S3 artifact가 없어도 Result가 `not_requested`를 반환해 Front 조회를 끝낸다.

심층 요청은 같은 `job_id`, `attempt`, `context_revision`, `result_revision`으로 서버의 `run_requested_deep_analysis()`에 연결한다. 이 bridge는 `load_deep_input()`으로 내부 Builder·Judgment·매핑을 읽고 기존 `run_l4`에 `initial_findings`와 `previous_judgment`를 전달한다. L4 서비스의 Store·publisher·tool registry·모델·실행 한도를 호출자가 주입한다. 이 후보 ZIP에는 L4 실행 환경을 넣지 않으며, bridge는 L4 서비스 쪽에서 사용한다. 실제 HTTP 시작 라우트, 모델·Tool 실행과 캡처 생성은 이 패키지 생성기의 동작이 아니다.

## 검증과 현재 경계

```powershell
python -X utf8 -B -m pytest -q tests/test_fast_result_deployment.py
```

focused 검사는 보존된 직접/queued ASL의 변환, attempt 초기화와 결과 참조, accepted/failed/invalid 분기, package import와 Result의 공개 JSON 소비를 확인한다. 예외적인 URL 반례나 새 판정 정책을 추가하지 않는다.

생성 명령 자체가 세 ZIP을 임시 경로에 풀고 `python -I -S`로 저장소·site-packages·PYTHONPATH와 분리하여 import한다. Result는 SDK 대역에서 받은 합성 공개 결과로 handler를 호출하고 그대로 반환하는지 확인한다. 기본 호환 패키지에서는 실제로 포함한 v2 모듈들도 import하고 기존 요청 계약 helper를 실행한다. **실제 AWS·provider 호출은 0회다.** SDK 대역은 ZIP에 포함되지 않는다. 저장소 모듈이 우연히 import돼 패키지 누락이 가려지는 일을 방지하는 검사다.

이 문서의 2026-10-02 로컬 실행 당시에는 라이브 AWS 인증 경로가 확인되지 않았다. 2026-10-03 사용자가 제공한 AWS 로그인으로 실제 환경 확인을 별도 진행하고 있으며, 로컬 후보를 운영 배포 완료로 표시하지 않는다. 실제 적용 시에는 선택한 Lambda/ASL/API 경로와 권한을 확인한 뒤 동일 입력이 저장 record → Builder → 실제 모델 요청 → 공개 Result로 이어지는 결과를 별도로 남긴다.

### 2026-10-02 로컬 실행 기록

- 지정 focused 검사: **10 passed**. `evaluation/remediation-20261002/fast-result-implementation/deployment-tests.txt`.
- 기본 호환 후보와 실제 격리 import/호출 기록: 같은 작업 폴더의 `aws-candidate-compatible/`.
- 기본 호환 방식을 보완하기 전에 만든 두 파일 최소 후보는 `aws-candidate-example/`에 보존했다. 이는 기본 배포 후보를 대신하지 않는다.
- 후보의 모델명·ARN은 위 명령의 예시값이다. 각 ZIP과 생성 당시 소스는 manifest의 hash로 구별하며, 이후 소스가 바뀌면 새 출력 디렉터리에 다시 생성한다.
- 최종 Result의 접속 차단 종료 처리를 포함한 현재 후보는 `aws-candidate-final-r4/`다. 세 ZIP 격리 검사를 다시 통과했다. 최종 보완 관련 44개 검사 통과는 `verification-r4.txt`에 기록했다. 앞선 회귀·focused 검사와 겹치므로 검사 수를 합산하지 않는다.

### 2026-10-03 Sonnet 5.5·Opus 5.5 비교용 전송 설정

사용자는 Sonnet 5.5로 수행하고 Opus 5.5를 같은 입력으로 비교하도록 지정했다. 공식 Messages 모델 ID는 `claude-sonnet-5-5`, `claude-opus-5-5`다. 두 모델은 기본값이 아닌 temperature를 거부하며, `thinking`을 생략하면 adaptive thinking을 사용한다. `output_config.effort`로 비교 수준을 명시한다. [Sonnet 5.5 문서](https://platform.claude.com/docs/en/models/sonnet-5-5/migration-guide), [Opus 5.5 문서](https://platform.claude.com/docs/en/models/opus-5-5/migration-guide).

`AnthropicGateway`에 명시 옵션 `omit_temperature=True`, `output_effort='high'`를 추가했다. 모델명에 따른 자동 변경이나 대체 모델 선택은 없다. 옵션이 없으면 기존 `temperature: 0` 전송을 유지한다. 응답은 기존 방식대로 `type=text` 블록만 읽으므로 앞에 thinking 블록이 있어도 처리한다. `max_tokens` 종료는 서비스 실패로 남기며 URL의 `UNKNOWN` 판정으로 만들지 않는다.

| 설정 | 비교 실행값 |
|---|---|
| handler | `evidence_pipeline.aws_runtime.handler` |
| `EVIDENCE_ROLE` / `EVIDENCE_RESULT_CONTRACT` | `judgment` / `fast-result-1` |
| `JUDGMENT_MODEL` | provider에서 실제 지원을 확인한 지정 모델 ID 그대로 |
| `ANTHROPIC_OMIT_TEMPERATURE` | `1` |
| `ANTHROPIC_OUTPUT_EFFORT` | `high` |
| `JUDGMENT_MAX_TOKENS` | `8192` |
| `LLM_TIMEOUT_SECONDS` | `120` |
| Judgment Lambda / SFN Task timeout | `150` / `180`초 |

후보 생성 시 기존 명령에 다음 옵션을 더한다. `--model`에는 각 실행의 정확한 모델 ID를 전달한다. 확인된 ARN·base URL·secret ID를 사용하고 기존 r4 출력은 덮어쓰지 않는다.

```powershell
$candidateArgs += @(
  '--omit-temperature', '--output-effort', 'high', '--max-tokens', '8192',
  '--model-timeout', '120', '--lambda-timeout', '150', '--task-timeout', '180'
)
python -X utf8 -B @candidateArgs
```

앞의 `$candidateArgs`를 실제 입력·새 출력 경로·확인한 provider 설정으로 구성한 뒤 실행한다. 두 모델을 비교할 때는 같은 버전의 system prompt와 Builder user 본문을 사용한다. 구현 중 지시를 명확히 한 이력은 승인 원문과 구분해 보존한다. 같은 본문·prompt, high, 출력 예약과 timeout을 사용하며 실제 응답의 model ID·종료 상태·usage·지연을 기록한다. 새 생성 옵션을 포함하므로 r4 이후 소스로 ZIP을 다시 생성해야 한다.

provider가 지정 모델을 지원하지 않으면 해당 비교 결과를 미수행으로 남긴다. 공식 모델 존재가 현재 router의 지원을 뜻하지 않는다. 실제 환경 확인과 수집기 호환성 절차는 [AWS 최종 점검 계획](../../../remediation-20261002/fast-result-implementation/aws-final-check/environment-plan.md)에 구분해 기록한다.

### 실제 연결 확인 — 2026-10-03

Sonnet 5.5와 Opus 5.5의 공식 존재를 확인했다. 현재 프로젝트의 MonoRouter Claude Code 모델 목록에는 Opus 5.5가 있으며, Sonnet 5.5의 정확한 ID 요청은 HTTP 400 `requested model is not supported`로 거절된다. AWS Bedrock에는 두 모델과 global inference profile이 있으나 계정의 `agreementAvailability=NOT_AVAILABLE`이다. 새 약관 수락과 첫 Bedrock 호출은 승인 전까지 수행하지 않는다. [지원 확인 기록](../../../remediation-20261002/fast-result-implementation/aws-final-check/model-support-findings.md)을 참고한다.

실제 provider 호출에서 기본 Python User-Agent 요청은 Cloudflare 403/1010으로 차단됐고, 같은 요청에 `User-Agent: team5-url-analysis/1.0`을 명시하면 Opus 5.5 응답을 받았다. Gateway에 이 서비스 식별자를 적용했다. 인증·대상 주소·응답 처리 방식은 그대로다.

`aws-final-check/actual-results/`의 Opus 결과는 보관된 네 통제 입력의 Builder 본문을 실제 모델에 보낸 실험이다. Lambda·Step Functions로 새 수집부터 실행한 결과와 구분한다. 각 시도의 system/body 해시와 provider 원본을 보존하며, 실제 모델 응답을 코드로 다른 판정으로 바꾸지 않는다.

현재 Context/Judgment 역할에는 새 fast artifact 쓰기 권한이 없고, CodeBuild 역할에는 새 source 객체 읽기 권한이 없다. 해당 임시 권한 제안과 빌드·Lambda 후보는 준비했지만 적용하지 않았다. 실제 StartBuild inline 요청은 buildspec 25,600자 한계로 거절되어 Build ID·이미지 push가 없었다. API 운영 라우팅과 Lambda/SFN 배포는 변경하지 않았다.
