"""L2-C-04 자체 서명 인증서 Analyzer

[목적] 서버 인증서가 자체 서명인지 확인한다. 체인 신뢰와 URL 위험도는 별도 검사 대상이다.

[입력]  TLS Raw Data의 leaf_certificate.self_signed (+ subject/issuer는 근거 보존용)
[출력]  Signal evidence{subject, issuer}

[판정 기준 — 서명 실검증]
subject/issuer 문자열 비교가 아니라, Collector가 파싱 시점에 인증서 서명을
자기 공개키로 검증한 결과(leaf_certificate.self_signed)를 그대로 쓴다.
이름만 issuer==subject로 꾸미고 실제로는 다른 키로 서명한 인증서까지 구분된다.
Analyzer는 Raw Data만 읽는 순수 로직이라(네트워크, 원문 접근 없음) 검증 자체는
DER 원문을 가진 Collector의 몫이고, 여기서는 그 관측값을 Signal로 정리만 한다.

detected: true(자체 서명) / false(자체 서명 아님; CA 신뢰 여부는 별도) / null(인증서를 못 봤거나 검증 불가)
"""

SIGNAL = {"id": "L2-C-04", "scanner": "certificate", "name": "self_signed_certificate"}


def analyze(tls: dict) -> dict:
    leaf = tls["leaf_certificate"]

    return {
        **SIGNAL,
        # 인증서를 못 봤으면 판정 자체가 불가 -> null (unknown != 자체 서명 아님)
        "detected": leaf["self_signed"] if leaf else None,
        "evidence": {
            "subject": leaf["subject"] if leaf else None,
            "issuer": leaf["issuer"] if leaf else None,
        },
    }
