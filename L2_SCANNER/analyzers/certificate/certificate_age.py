"""L2-C-01 인증서 발급 기간 Analyzer

[목적] 최근 발급된 인증서인지 확인한다.
       피싱 사이트는 수명이 짧아 "며칠 전 발급된 인증서"가 자주 관측된다.

[입력]  TLS Raw Data의 leaf_certificate.not_before
[출력]  Signal evidence{age_days, fresh}

[판정]
age_days = 오늘(UTC) - notBefore. fresh = age_days가 기준일(FRESH_CERT_MAX_AGE_DAYS) 이하.
detected는 fresh와 동일 — "최근 발급 패턴이 관측되었는가". 신규 정상 사이트도 fresh일 수
있으므로 악성 판정이 아니다 (해석은 Rule/LLM 몫).

네트워크 접속 없음 — Certificate Collector가 수집·파싱한 값을 재사용한다.
"""

from datetime import datetime, timezone

# '최근 발급'으로 볼 기준일 — 지식 데이터. 명세서에 기준값이 없어 초기값으로 두며 팀 협의 대상.
FRESH_CERT_MAX_AGE_DAYS = 30


def analyze(tls: dict) -> dict:
    leaf = tls["leaf_certificate"]

    age_days = None
    fresh = None
    if leaf and leaf["not_before"]:
        not_before = datetime.fromisoformat(leaf["not_before"])
        age_days = (datetime.now(timezone.utc) - not_before).days
        # 음수 age(= notBefore가 미래)는 '최근 발급'이 아니라 별개 이상 신호로,
        # L2-C-02가 not_valid로 관측한다 → 여기서는 fresh로 치지 않는다
        fresh = 0 <= age_days <= FRESH_CERT_MAX_AGE_DAYS

    return {
        "id": "L2-C-01",
        "scanner": "certificate",
        "name": "certificate_age",
        # 인증서를 못 봤으면(null) 미관측 false — unknown ≠ fresh
        "detected": bool(fresh),
        "evidence": {
            "age_days": age_days,
            "fresh": fresh,      # 확인 못 했으면 null ("확인 안 됨" ≠ "아니다")
        },
    }
