"""L2-C-04 자체 서명 인증서 Analyzer

[목적] CA가 아니라 스스로 서명한 인증서인지 확인한다.
       정식 CA 검증을 거치지 않은 인증서 — 테스트 서버나 악성 인프라에서 흔한 패턴.

[입력]  TLS Raw Data의 leaf_certificate.subject / issuer (+ chain_error 참고)
[출력]  Signal evidence{subject, issuer}

[판정 기준]
subject == issuer (자기가 자기를 발급). 자체 서명 인증서의 정의 그대로이며,
Collector의 1차 검증에서도 self-signed certificate 계열 오류(chain_error)로 함께 관측된다.
※ 서명을 공개키로 직접 검증하는 완전한 판정도 가능하지만, subject/issuer 동일성이
   표준적인 1차 판별 기준이고 chain_error가 교차 근거가 되므로 현재는 이 기준을 쓴다.

네트워크 접속 없음 — Certificate Collector가 수집·파싱한 값을 재사용한다.
"""


def analyze(tls: dict) -> dict:
    leaf = tls["leaf_certificate"]

    subject = leaf["subject"] if leaf else None
    issuer = leaf["issuer"] if leaf else None

    # 둘 다 확인된 경우에만 판정 — 인증서를 못 봤으면 미관측 (unknown ≠ 자체 서명 아님)
    self_signed = (subject == issuer) if (subject and issuer) else False

    return {
        "id": "L2-C-04",
        "scanner": "certificate",
        "name": "self_signed_certificate",
        "detected": self_signed,
        "evidence": {
            "subject": subject,
            "issuer": issuer,
        },
    }
