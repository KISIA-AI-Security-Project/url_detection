"""L2-C-06 CT 최초 관측 시점 Analyzer

[목적] 인증서가 CT(Certificate Transparency) 로그에 최초로 관측된 시점을 파악한다.
       피싱 인증서는 방금 만들어진 것이 많은데, notBefore(C-01)는 발급자가 쓰는 값이라
       조작 여지가 있는 반면 CT 관측 시각은 제3자(공개 로그)의 기록이다 - 교차 확인 재료.

[입력]  CT Raw Data (collectors/ct_collector.py 출력 - crt.sh 조회 결과)
[출력]  Signal evidence{first_seen, age_days, fresh}

[판정]
age_days = 오늘(UTC) - first_seen. fresh = age_days가 기준일 이하.
기준일은 C-01과 같은 값(config.knowledge.FRESH_CERT_MAX_AGE_DAYS)을 공유한다 -
같은 최근 지식을 두 곳에서 따로 관리하지 않기 위함 (조정도 한곳에서).
detected는 fresh와 동일 - CT에 최근 처음 등장한 인증서인가. 판정은 Rule/LLM 몫.

조회 실패, CT 미기록이면 null(unknown) 보고 - 확인 안 됨 != 아니다.
네트워크 접속 없음 - CT Collector가 조회한 값을 계산만 한다.

"""

from datetime import datetime, timezone

from l2_scanner.config.knowledge import FRESH_CERT_MAX_AGE_DAYS

SIGNAL = {"id": "L2-C-06", "scanner": "certificate", "name": "ct_first_seen"}


def analyze(ct: dict) -> dict:
    first_seen = ct["first_seen"]

    age_days = None
    fresh = None
    if first_seen:
        observed = datetime.fromisoformat(first_seen)
        age_days = (datetime.now(timezone.utc) - observed).days
        # 미래 시각(음수 age)은 최근 관측이 아니라 시계 오차,이상 데이터 - fresh로 치지 않는다
        fresh = 0 <= age_days <= FRESH_CERT_MAX_AGE_DAYS

    return {
        **SIGNAL,
        # 조회 못 했으면 판정 불가 -> null - unknown != fresh 아님 
        "detected": fresh,
        "evidence": {
            "first_seen": first_seen,
            "age_days": age_days,
            "fresh": fresh,      # 확인 못 했으면 null (확인 안 됨 != 아니다)
        },
    }
