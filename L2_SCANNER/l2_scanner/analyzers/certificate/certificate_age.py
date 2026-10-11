"""L2-C-01 인증서 유효기간 시작 후 경과일 측정.

[입력] Collector의 leaf_certificate.not_before(인증서 유효기간 시작 시각).
[출력] 측정 여부와 evidence{not_before, measured_at, age_days}.
분석 기준 시각에서 notBefore를 뺀 정수 일수를 보존한다. 미래 시작 시각은
음수로 남긴다. 임계값, 최근 여부, 발급일 또는 도메인 생성일 판정을 만들지 않는다.
네트워크 접속 없음 — Certificate Collector가 수집한 값을 재사용한다.
"""

from datetime import datetime, timezone

SIGNAL = {"id": "L2-C-01", "scanner": "certificate", "name": "certificate_age",
          "result_kind": "measurement"}


def analyze(tls: dict) -> dict:
    leaf = tls["leaf_certificate"]

    measured_at = datetime.now(timezone.utc)
    not_before = leaf.get("not_before") if leaf else None
    age_days = None
    if not_before:
        age_days = (measured_at - datetime.fromisoformat(not_before)).days

    result = {
        **SIGNAL,
        "measurement_state": "observed" if age_days is not None else "unavailable",
        "evidence": {
            "not_before": not_before,
            "measured_at": measured_at.isoformat(),
            "age_days": age_days,
        },
    }
    if age_days is None:
        result["limitations"] = [{
            "code": "certificate_not_before_unavailable", "stage": "analysis",
            "impact_scope": "analysis", "analyzer": SIGNAL["id"],
            "occurrence_id": "l2:analysis:L2-C-01:not_before",
            "target": {"hostname": tls.get("hostname")},
            "message": "Collected TLS data has no certificate validity start time for this measurement.",
        }]
    return result
