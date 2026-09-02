"""L2-H-02 리다이렉트 도메인 변경 Analyzer

[목적] 리다이렉트 과정에서 소유 단위 도메인(eTLD+1)이 바뀌는지 센다.
       예: example.com -> short.net -> login.example.xyz 는 소유자가 2번 바뀐 여정.

[입력]  Raw Data의 original_url, redirect_chain[]
[출력]  Signal evidence{domain_change_count, unique_domain_count, original_etld1, final_etld1, final_domain_changed}

[왜 전체 URL이 아니라 eTLD+1로 비교하는가]
login.example.com -> pay.example.com 은 같은 소유자 안에서의 이동이다.
이걸 도메인 변경으로 세면 정상 사이트가 대량 오탐된다. 그래서 소유 단위
(eTLD+1: example.com, example.co.kr)로 정규화한 뒤 비교한다.
eTLD+1 추출은 공용 유틸(utils/http_parsing.etld1)을 사용 - L2-H-04와 같은 기준.

detected: true(변경 관측) / false(응답은 받았고 변경 없음) / null(여정 관측 불가)
네트워크 접속 없음 - L2-H-01의 Collector가 수집한 redirect_chain[]을 재사용한다.
"""

from l2_scanner.utils.http_parsing import etld1

SIGNAL = {"id": "L2-H-02", "scanner": "header", "name": "redirect_domain_change"}


def analyze(raw: dict) -> dict:
    # 여정의 전체 지점 목록 = 출발점 + 각 hop의 목적지
    urls = [raw["original_url"]] + [h["destination_url"] for h in raw["redirect_chain"]]
    etld1_list = [etld1(u) for u in urls]

    # 이웃한 두 지점을 순서대로 비교해 소유자가 바뀐 횟수를 센다.
    # zip(리스트, 리스트[1:]) = (0번,1번), (1번,2번), ... 인접 쌍 순회
    change_count = sum(1 for a, b in zip(etld1_list, etld1_list[1:]) if a != b)

    # hop도 최종 응답도 없으면 여정 자체를 관측 못 함 -> 판정 불가 (unknown != 변경 없음)
    if not raw["redirect_chain"] and raw["final_url"] is None:
        detected = None
    else:
        detected = change_count > 0   # 변경이 1회 이상 관측되었는가 (악성 판정 아님)

    return {
        **SIGNAL,
        "detected": detected,
        "evidence": {
            "domain_change_count": change_count,             # 소유자가 바뀐 횟수
            "unique_domain_count": len(set(etld1_list)),     # 여정에 등장한 서로 다른 소유자 수
            "original_etld1": etld1_list[0],                 # 출발 소유자
            "final_etld1": etld1_list[-1],                   # 도착 소유자
            # 출발!=도착이면 특히 피싱 판단에서 가중치 높은 근거 (해석은 Rule/LLM 몫)
            "final_domain_changed": etld1_list[0] != etld1_list[-1],
        },
    }
