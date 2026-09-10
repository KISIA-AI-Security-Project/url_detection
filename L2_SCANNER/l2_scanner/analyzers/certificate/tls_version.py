"""L2-C-07 TLS 버전 Analyzer (명세서 5장 추가 구현: TLS Version 분석)

[목적] 폐기된 TLS 프로토콜(1.1 이하)로 협상됐는지 확인한다.
       TLS 1.0/1.1은 RFC 8996(2021)으로 공식 폐기됐고 주요 브라우저도 2020년에
       지원을 끊어서, 관리되는 정상 서비스는 자연히 1.2+로 올라간다.
       낡은 버전 = 방치되거나 급조된 인프라(버리는 피싱 서버)의 흔적.

[입력]  TLS Raw Data의 tls_version (handshake 협상 결과)
[출력]  Signal evidence{tls_version, legacy}

[정상에서도 나타나는 조건 - 관측 != 판정]
레거시 장비, 구형 사내 시스템도 낡은 TLS를 쓸 수 있다. detected는 폐기 표준
사용의 관측일 뿐 악성 판정이 아니다 (해석은 Rule/LLM 몫).

detected: true(1.1 이하 관측) / false(1.2+ 관측) / null(TLS 접속 실패 = 확인 불가)
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
