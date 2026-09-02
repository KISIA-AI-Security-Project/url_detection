"""리다이렉션 체인 Analyzer - Raw Data를 읽어 Signal을 만든다.
네트워크 접속 없음. 이미 수집된 값의 정리, 계산만 수행.

detected: true(리다이렉트 관측) / false(응답은 받았고 리다이렉트 없음) / null(여정을 전혀 관측 못 함 - 첫 접속부터 실패) (unknown != 없음)
"""

SIGNAL = {"id": "L2-H-01", "scanner": "header", "name": "redirect_chain"}


def analyze(raw: dict) -> dict:
    chain = raw["redirect_chain"]

    # hop도 최종 응답도 없다 = 첫 접속부터 실패 -> 여정 자체를 관측 못 함 (검사 불가)
    if not chain and raw["final_url"] is None:
        detected = None
    else:
        detected = len(chain) > 0   # 리다이렉트가 관측되었는가

    return {
        **SIGNAL,
        "detected": detected,
        "evidence": {
            "redirect_count": len(chain),
            "final_url": raw["final_url"],
            "chain": [hop["destination_url"] for hop in chain],
        },
    }
