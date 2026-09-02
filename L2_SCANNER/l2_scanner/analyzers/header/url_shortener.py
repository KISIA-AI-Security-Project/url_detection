"""L2-H-04 단축 URL Analyzer

[목적] 여정에 URL 단축 서비스(bit.ly 등)가 끼어 있는지 확인하고, 단축이 풀린 실제 목적지(resolved_url)를 제공한다.

[입력]  Raw Data의 original_url, redirect_chain[], final_url
[출력]  Signal evidence{shortener_domain, resolved_url}

[판단 기준]
"단축 URL인가"는 URL 문자열 모양만으로는 알 수 없음.
그래서 알려진 단축 서비스 명단과의 대조로 판단한다.
- 명단에 있으면: 오탐 없이 확정 탐지
- 명단에 없는 신생 서비스는: 여기서는 놓치지만(미탐), 그 행동(다른 소유자로의
리다이렉트)은 L2-H-01·02가 관측하므로 시스템 차원에서는 잡힌다.
이 기능의 고유 가치 = 목적지 은닉 도구를 썼다는 의도 정보 + 숨겨진 진짜 목적지.

[L0과의 역할 분담]
L0은 접속 전에 원본 URL 문자열만 보고 판별하고, L2는 접속 후 여정 전체에서
단축 서비스 경유를 관측하며 resolved_url을 제공한다. 중복이 아닌 보완 관계.

네트워크 접속 없음 - L2-H-01의 Collector가 수집한 Raw Data를 재사용한다.
"""

from l2_scanner.config.knowledge import SHORTENER_DOMAINS   # 단축 서비스 명단 - 지식 데이터는 config에서 관리
from l2_scanner.utils.http_parsing import etld1

SIGNAL = {"id": "L2-H-04", "scanner": "header", "name": "url_shortener"}


def analyze(raw: dict) -> dict:
    # 검사 대상 = 출발 URL + 각 hop의 목적지.
    # 출발 URL 포함 이유: 사용자가 받은 링크 자체가 단축 URL인 게 가장 흔한 패턴
    # 중간 목적지 포함 이유: 여정 중간에 단축 서비스를 끼워 추적을 세탁하는 패턴 대비
    urls = [raw["original_url"]] + [h["destination_url"] for h in raw["redirect_chain"]]

    # eTLD+1로 정규화해 대조 - api.bit.ly 같은 서브도메인 운용도 잡기 위함 (공용 유틸 사용)
    found = [(u, etld1(u)) for u in urls if etld1(u) in SHORTENER_DOMAINS]

    # 출발 URL은 문자열만으로 대조 가능하므로 발견(true)은 여정 관측과 무관하게 확정.
    # 반대로 미발견(false)은 여정을 실제로 관측했을 때만 말할 수 있다 
    # 첫 접속부터 실패해 중간 경유를 전혀 못 봤으면 판정 불가(null). (unknown != 미사용)
    if found:
        detected = True
    elif not raw["redirect_chain"] and raw["final_url"] is None:
        detected = None
    else:
        detected = False

    # resolved_url은 단축이 실제로 풀린 경우에만 기록한다.
    # 죽은 링크(삭제, 만료, 차단)는 리다이렉트가 없어서 final_url이 원본 그대로인데,
    # 그걸 resolved_url에 넣으면 단축이 이 주소로 풀렸다는 거짓 정보가 된다
    # -> detected는 true(사용 자체는 관측), resolved_url은 null(풀린 목적지는 확인 못 함)
    resolved = raw["final_url"] if (found and raw["redirect_chain"]) else None

    return {
        **SIGNAL,
        "detected": detected,
        "evidence": {
            "shortener_domain": found[0][1] if found else None,  # 첫 번째로 발견된 단축 도메인
            "resolved_url": resolved,
        },
    }
