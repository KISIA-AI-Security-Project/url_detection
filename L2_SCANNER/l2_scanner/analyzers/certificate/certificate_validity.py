"""L2-C-02 인증서 유효성 Analyzer

[목적] 만료되었거나 아직 유효하지 않은 인증서를 확인한다.

[입력]  TLS Raw Data의 leaf_certificate.not_before / not_after
[출력]  Signal evidence{status, not_before, not_after}

[판정] 현재 시각(UTC)을 유효기간과 비교:
    now < not_before          -> "not_valid" (아직 유효하지 않음)
    now > not_after           -> "expired"   (만료)
    not_before ≤ now ≤ after  -> "valid"
    인증서를 못 봄            -> null (unknown)
detected = 비정상 상태(expired/not_valid)가 관측되었는가.
status 값 이름(valid/expired/not_valid)은 노션 L2-C-02 페이지에서 정의한 팀 표기를 따른다.

네트워크 접속 없음 - Certificate Collector가 수집, 파싱한 값을 재사용한다.
"""

from datetime import datetime, timezone

SIGNAL = {"id": "L2-C-02", "scanner": "certificate", "name": "certificate_validity"}


def analyze(tls: dict) -> dict:
    leaf = tls["leaf_certificate"]

    status = None
    not_before = leaf["not_before"] if leaf else None
    not_after = leaf["not_after"] if leaf else None

    if leaf and not_before and not_after:
        now = datetime.now(timezone.utc)
        if now < datetime.fromisoformat(not_before):
            status = "not_valid"
        elif now > datetime.fromisoformat(not_after):
            status = "expired"
        else:
            status = "valid"

    return {
        **SIGNAL,
        # 비정상 유효성(expired/not_valid) 관측이 true. 확인 못 함(status null)은
        # 판정 불가 -> null - unknown != 비정상 
        "detected": None if status is None else status in ("expired", "not_valid"),
        "evidence": {
            "status": status,
            "not_before": not_before,
            "not_after": not_after,
        },
    }
