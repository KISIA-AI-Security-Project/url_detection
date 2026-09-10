"""L2-C-08 와일드카드 인증서 Analyzer (명세서 5장 추가 구현: Wildcard Certificate 탐지)

[목적] 인증서 SAN에 와일드카드(*.도메인) 항목이 있는지 확인한다.
       와일드카드 인증서 하나로 login-bank.evil.com 같은 피싱 서브도메인을
       무한 생성할 수 있고, 서브도메인마다 인증서를 새로 받으면 CT 로그에
       흔적이 남지만 와일드카드는 한 장으로 가려진다.

[입력]  TLS Raw Data의 leaf_certificate.san[]
[출력]  Signal evidence{wildcard_names, san_count}

[통계 검증 대상 - 6주차 회의 안건 11]
와일드카드는 정상 서비스(CDN, SaaS)에서도 매우 흔하므로 이 신호의 단독 판정력은
낮다. 본 목적은 정상·악성 데이터셋에서 와일드카드 비율 차이를 통계로 확인하는 것
- detected는 그 통계의 원재료다. 대량 테스트에서 차이가 없으면 제거 후보.

detected: true(와일드카드 관측) / false(인증서 봤고 와일드카드 없음) / null(인증서 확인 불가)
네트워크 접속 없음 - Certificate Collector가 수집·파싱한 SAN을 재사용한다.
"""

SIGNAL = {"id": "L2-C-08", "scanner": "certificate", "name": "wildcard_certificate"}


def analyze(tls: dict) -> dict:
    leaf = tls["leaf_certificate"]

    if not leaf:
        # 인증서를 못 봤으면 판정 불가 -> null (확인 안 됨 != 와일드카드 없음)
        detected = None
        wildcard_names = []
        san_count = None
    else:
        san = leaf["san"] or []
        # 인증서 와일드카드는 가장 왼쪽 라벨만 허용되므로(*.example.com) 접두 검사로 충분
        wildcard_names = [name for name in san if name.startswith("*.")]
        detected = len(wildcard_names) > 0
        san_count = len(san)

    return {
        **SIGNAL,
        "detected": detected,
        "evidence": {
            "wildcard_names": wildcard_names,
            "san_count": san_count,   # 통계용 보조 관측 (SAN 규모 - 안건 11의 SAN 상세 분석 재료)
        },
    }
