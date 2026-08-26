"""L2-C-05 인증서 체인 신뢰성 Analyzer

[목적] 정상적인 CA 신뢰 체인이 구성되는지 확인한다.
       leaf → 중간 CA → 루트 CA로 이어지는 서명 사슬이 OS 신뢰 저장소까지 닿는가.

[입력]  TLS Raw Data의 chain_valid / chain_error / certificate_chain[]
[출력]  Signal evidence{valid, chain_depth, error}

[검증은 누가 했나]
실제 체인 검증은 Collector의 1차 handshake(verify_mode=CERT_REQUIRED)가 수행했다
(OS 신뢰 저장소 기준). 이 Analyzer는 그 결과를 Signal로 정리만 한다.
- chain_valid=true  → 신뢰 체인 구성 확인
- chain_valid=false → 검증 실패 관측. 사유 원문은 error에 (self-signed / expired /
                      unable to get local issuer 등 — 다른 C 신호와의 교차 근거)
- chain_valid=null  → TLS 자체가 안 됨 = 확인 못 함 (unknown ≠ 비정상)

네트워크 접속 없음 — Certificate Collector가 수집·파싱한 값을 재사용한다.
"""


def analyze(tls: dict) -> dict:
    valid = tls["chain_valid"]
    chain = tls["certificate_chain"]

    return {
        "id": "L2-C-05",
        "scanner": "certificate",
        "name": "certificate_chain",
        # '체인 비정상이 관측됨'이 신호 — 확인 못 함(null)은 false
        "detected": valid is False,
        "evidence": {
            "valid": valid,
            # 서버가 제시한 체인 길이 (leaf 포함). 못 봤으면 null
            "chain_depth": len(chain) if chain else None,
            "error": tls["chain_error"],   # 검증 실패 사유 원문 보존
        },
    }
