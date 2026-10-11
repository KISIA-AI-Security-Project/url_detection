"""L2-C-07 TLS 버전 Analyzer (명세서 5장 추가 구현: TLS Version 분석)

[목적] 폐기된 TLS 프로토콜(1.1 이하)로 협상됐는지 확인한다.
       성공한 연결에서 사용한 버전이며 서버가 지원하는 전체 버전 목록은 아니다.
       버전만으로 사이트의 악성/정상이나 피싱 운영을 판단하지 않는다.
       수집 결과는 raw/record에 보존하고 악성 URL 판단용 Builder에서는 제외한다.

[입력]  TLS Raw Data의 tls_version (handshake 협상 결과)
[출력]  Signal evidence{tls_version, legacy}

[정상에서도 나타나는 조건 - 관측 != 판정]
레거시 장비, 구형 사내 시스템도 낡은 TLS를 쓸 수 있다. detected는 폐기 표준
사용의 관측일 뿐 악성 판정이 아니다 (해석은 Rule/LLM 몫).

detected: true(아래 구형 목록에 해당) / false(목록 밖) / null(수집된 버전 없음)
네트워크 접속 없음 - Certificate Collector가 수집한 값을 재사용한다.
"""

SIGNAL = {"id": "L2-C-07", "scanner": "certificate", "name": "tls_version"}

# RFC 8996 폐기 대상 - 표준 의미론이므로 조정값(config)이 아니라 여기 둔다 (REDIRECT_CODES와 같은 성격)
LEGACY_TLS_VERSIONS = frozenset({"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"})


def analyze(tls: dict) -> dict:
    version = tls["tls_version"]

    # handshake 자체를 못 했으면 버전 확인 불가 -> null (확인 안 됨 != 최신)
    legacy = None if version is None else version in LEGACY_TLS_VERSIONS

    return {
        **SIGNAL,
        "detected": legacy,
        "evidence": {
            "tls_version": version,
            "legacy": legacy,
        },
    }
