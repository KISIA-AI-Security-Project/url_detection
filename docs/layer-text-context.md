# 승인된 계층의 모델 입력 본문

2026-09-29. 본문 버전은 `layer-text-1`이며 내부 사실 선별 버전은 기존
`decision-evidence-11`이다. 사용자 합의에 따라 원본·record·내부 근거 대응을
본문과 분리하고, 고정 템플릿으로 제목·항목·짧은 설명을 구성한다.

## 구현한 범위

- 2026-10-02 JS **사용자 검토 전 후보**: l3_javascript_text.py는 J01~J09를 소스 확보 범위·코드 문맥·변환·입력과 요청·환경 분기 관계로 선별한다. l3_content_text.py는 HTML v2와 JS를 묶고 선택적으로 L0/L1/L2를 앞에 둔다. 본문 버전은 각각 l3-javascript-text-1, l3-content-text-1이다. 전체 raw/native/record와 개별 원인 발생은 내부에 보존하고 실제 Messages 직전에 같은 입력으로 문서 전체를 재구성한다. [현재 JS 후보와 동일 입력 결과](../../../remediation-20261002/javascript-context/README.md)를 따른다.
- `l01_text.py`: 기존 L0 관찰과 판단 안내를 보존하고, L1 조회 대상·IP/ASN·NS 관계·등록 정보를 직접 읽히게 표현한다. 등록 단위 NS 오류 응답 수정도 유지한다.
- `l2_text.py`: 승인된 H01–H09, C01–C08의 선택을 사용한다. 응답별 HTTP 사실과 수집 범위를 함께 배치하고, 같은 TLS 관측의 인증서 정보를 한 구획에 모은다. 참조는 코드에서 해결하며 본문에 E-ID를 쓰지 않는다. C07/C08 생략과 C03 와일드카드 대조 근거는 유지한다.
- `l3_html_text.py` (2026-10-02): HTML H01~H08과 주변 선언을 같은 raw/record에서 직접 선택한다. 폼·입력·제출 경로·브랜드 정책·리소스·base·refresh를 주체별로 구성하고, JavaScript 범위를 구별한다. 현재 본문 버전은 `l3-html-text-2`이다. 브랜드는 주소 대조에 선택된 대상으로 표시하고, 생산 결과의 확신 등급은 내부 보존하며 기록된 선택 근거의 위치를 전달한다. [v2 변경과 재현 자료](../../../remediation-20261002/html-brand-context-v2/README.md) 및 [최초 HTML 전달 계약](../../../remediation-20261001/html-context/README.md)을 따른다.
- `model_text.py`: 각 계층 블록을 하나의 본문으로 조립한다. 본문 구간과 원본 근거의 대응표는 audit에 남긴다. 이전 JSON을 뒤에 다시 붙이지 않는다.
- `prepare_text_messages`: 같은 본문을 실제 Gateway의 Messages 봉투에 넣는다.
- `call_text_messages`: 같은 본문으로 실제 Gateway 전송 함수를 호출하고 캡처한 요청의 동일성을 확인한다. 반환값은 검증 전 응답이며 URL 판정을 게시하지 않는다.

본문의 ASN/IANA ID·URL·원문 값·목록과 반복된 관측은 유지한다. 원본 추적 ID,
`evidence_ref`, `requested_url_index`, 내부 집계·빈 포장·저장 해시는 내부 대응표에
둔다. L0의 기존 판단 안내 문구를 이 표현 작업에서 임의 수정하지 않았다.

## 사용 경계

```python
from evidence_pipeline import build_text_context
from evidence_pipeline.model_text import prepare_text_messages, call_text_messages

audit = {}
document = build_text_context(records, raws, audit=audit)
# HTML이 포함된 명시 범위: build_text_context(records, raws, l3_scope='html', audit=audit)
# 검토·표시하는 내용은 document.body다.
document, request = prepare_text_messages(document, gateway, system_prompt)
# 전송을 승인한 실행에서만 호출한다. 반환값의 검증·게시는 별도 책임이다.
# unvalidated_output = call_text_messages(document, gateway, system_prompt)
```

이번 검증의 전송기는 실제 Gateway를 사용하되 opener를 오프라인 응답으로 대체했다.
검토용 TXT와 `request.json`의 user content가 일치한다. 모델 판단은 실행하지 않았다.

## 아직 완료로 취급하지 않는 부분

1. HTML은 build_html_text_context와 명시적 html 범위로 제공한다. JS 후보는 build_javascript_text_context, 통합 후보는 build_text_context(..., l3_scope='html_javascript', l3_native=native)로 제공하며 사용자 최종 검토를 앞두고 있다. 전체 L3 기본 경로는 TextContextNotReady를 유지한다. HTML 단독 문서는 JS가 범위 밖임을 표시하고 전체 JS 원본·record를 audit에 보존한다.
2. AWS 조정 계층이 붙이는 `url_activity_observation`의 별도 표시 역시 이번 계층별 승인에 포함하지 않았다. 이를 가진 문서도 임의 누락하지 않고 명시적으로 알린다. DNS 활동 판단 자체를 변경하지 않는다.
3. `judgment_prompt_v2.txt`와 기존 응답 검증·프론트 연결은 E-ID를 요구하는 기존 경로다. 모델에게 ID를 숨긴 채 ID를 선택하라고 요구하는 조합을 입력용 API가 거부한다. 새 응답 계약을 임의 확정하지 않았다.
4. 따라서 `aws_judgment_v2.judgment_v2`의 기본 실행을 새 본문으로 전환하거나 배포하지 않았다. 새 텍스트 입력 API의 전송 검증과 기존 운영 경로 전환 완료를 구분한다.

원본→생산 결과→record→선별→계층별 블록→통합 본문→캡처한 Messages는 확인했다.
검사 통과는 값·관계 보존과 전송 동일성의 확인이며 모델 이해도·정확도 또는 운영
연결의 완료 증거가 아니다. 형식별 모델 비교실험을 요구하지 않는다.

## 검증 자료

`../results/model-text-integration-20260929/`에 계층별·통합 사례의 본문, 내부 대응,
선별 audit, 캡처한 요청을 보존한다. 원본이 다른 사례를 한 사이트의 관측으로 합치지
않는다. `l012-same-url-controlled`는 동일 URL에 대해 통제한 L0/L1/L2 생산·저장·재조회
결과를 묶은 사례다. 기존 실제 저장 사례와 통제 입력은 `verification.json`에서 구분한다.

HTML의 동일 입력 검증은 `evaluation/remediation-20261001/html-context/`에 별도로
보존한다. 새 HTML 문서는 실제 Messages 준비 시 원본 입력으로 재구성하여 본문·블록·
source map 변경과 JSON 재유입을 거부한다. 범위 선택 전에 전체 입력 묶음을 검증한다.
