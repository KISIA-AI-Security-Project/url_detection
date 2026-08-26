"""리다이렉션 체인 Analyzer — Raw Data를 읽어 Signal을 만든다.
네트워크 접속 없음. 이미 수집된 값의 정리·계산만 수행."""


def analyze(raw: dict) -> dict:
    chain = raw["redirect_chain"]

    return {
        "id": "L2-H-01",            
        "scanner": "header",
        "name": "redirect_chain", 
        "detected": len(chain) > 0,  # 리다이렉트가 '관측되었는가' 
        "evidence": {
            "redirect_count": len(chain),
            "final_url": raw["final_url"],
            "chain": [hop["destination_url"] for hop in chain],
        },
    }