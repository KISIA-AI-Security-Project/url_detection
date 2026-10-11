"""L2-H-09 프로토콜 강등 Analyzer (명세서 5장 추가 구현: Protocol Transition 분석)

[목적] 리다이렉트 과정에서 HTTPS→HTTP 강등이 있었는지 확인한다.
       첫 URL은 HTTPS로 자물쇠 아이콘을 보여줘 신뢰를 얻고, 최종 콘텐츠는
       암호화 없는 서버(관리 쉬운 저가 인프라)에서 제공하는 패턴의 관측.

[입력]  Raw Data의 redirect_chain[]
[출력]  Signal evidence{downgrade_count, source_url, destination_url, upgrade_count}
        - source_url/destination_url은 첫 번째 강등 hop 기준

[detected 조건을 강등(HTTPS→HTTP)으로만 한정하는 이유]
반대 방향(HTTP→HTTPS 업그레이드)은 정상 사이트의 표준 동작(HSTS, 301 업그레이드)이라
전환 전체를 detected로 잡으면 오탐이 구조적으로 커진다. 업그레이드는 통계 분석용
보조 관측(upgrade_count)으로만 기록한다 (6주차 회의 안건 11 - 해석 필요한 값은 기록 후 통계).

detected: true(강등 hop 관측) / false(여정 관측했고 강등 없음) / null(여정 관측 불가)
네트워크 접속 없음 - L2-H-01의 Collector가 수집한 redirect_chain[]을 재사용한다.
"""

from urllib.parse import urlsplit

SIGNAL = {"id": "L2-H-09", "scanner": "header", "name": "protocol_downgrade"}


def _scheme(url: str) -> str | None:
    # urlsplit이 scheme을 소문자로 돌려주므로 대소문자 표기 차이로 어긋나지 않는다
    return urlsplit(url).scheme or None


def analyze(raw: dict) -> dict:
    downgrades = []
    upgrade_count = 0
    for hop in raw["redirect_chain"]:
        src, dst = _scheme(hop["source_url"]), _scheme(hop["destination_url"])
        if src == "https" and dst == "http":
            downgrades.append(hop)
        elif src == "http" and dst == "https":
            upgrade_count += 1

    # hop도 최종 응답도 없으면 여정 자체를 관측 못 함 -> 판정 불가 (H-03과 같은 기준)
    if not raw["redirect_chain"] and raw["final_url"] is None:
        detected = None
    else:
        detected = len(downgrades) > 0

    # evidence에는 첫 번째 강등 hop만 담는다 (H-03과 같은 방식)
    first = downgrades[0] if downgrades else {"source_url": None, "destination_url": None}

    return {
        **SIGNAL,
        "detected": detected,
        "evidence": {
            "downgrade_count": len(downgrades),
            "source_url": first["source_url"],
            "destination_url": first["destination_url"],
            "upgrade_count": upgrade_count,   # 통계용 보조 관측 (판정에 쓰지 않음)
        },
    }
