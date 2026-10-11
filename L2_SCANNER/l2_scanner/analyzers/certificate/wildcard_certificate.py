"""L2-C-08 와일드카드 인증서 Analyzer (명세서 5장 추가 구현: Wildcard Certificate 탐지)

[목적] 인증서 SAN에 와일드카드(*.도메인) 항목이 있는지 확인한다.
       현재 호스트와의 일치는 C03이 담당하며, 실제 하위 사이트 운영은 확인하지 않는다.

[입력]  TLS Raw Data의 leaf_certificate.san[]
[출력]  Signal evidence{wildcard_names, san_count}

[모델 전달 선택 - 2026-09-29]
수집·저장 결과를 유지하되 악성/정상 판단용 Builder의 별도 C08 항목에서는 제외한다.
C03의 실제 이름 대조 근거는 유지한다. 추가 통계 검증은 계획하지 않는다.

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
