"""L2-C-06: 수집한 CT 시각·출처와 검사 당시 경과일을 기록한다.

Collector가 고른 first_seen을 재사용하며, 최근 여부나 임계값 판정은 하지 않는다.
SCT/crt.sh 수집 방식은 그대로이고 별도의 네트워크 검증을 추가하지 않는다.
"""

from datetime import datetime, timezone

SIGNAL = {"id": "L2-C-06", "scanner": "certificate", "name": "ct_first_seen",
          "result_kind": "measurement"}


def analyze(ct: dict) -> dict:
    first_seen = ct["first_seen"]
    measured_at = datetime.now(timezone.utc)
    age_days = None
    if first_seen:
        observed = datetime.fromisoformat(first_seen)
        age_days = (measured_at - observed).days

    result = {
        **SIGNAL,
        "measurement_state": "observed" if age_days is not None else "unavailable",
        "evidence": {
            "first_seen": first_seen,
            "age_days": age_days,
            "measured_at": measured_at.isoformat(),
            "source": ct.get("source"),
        },
    }
    if age_days is None:
        result['limitations'] = [{'code': 'ct_timestamp_unavailable', 'stage': 'analysis',
            'impact_scope': 'analysis', 'analyzer': SIGNAL['id'],
            'occurrence_id': 'l2:analysis:L2-C-06:timestamp',
            'message': 'Collected CT data has no timestamp for this measurement.'}]
    return result
