"""L2-H-04 단축 URL Analyzer

[목적] 여정에 URL 단축 서비스(bit.ly 등)가 끼어 있는지 확인하고,
       단축이 풀린 실제 목적지(resolved_url)를 제공한다.

[입력]  Raw Data의 original_url, redirect_chain[], final_url
[출력]  Signal evidence{shortener_domain, resolved_url}

[판단 기준 — known-list 방식]
"단축 URL인가"는 URL 문자열 모양만으로는 알 수 없는 '세상에 대한 지식'이다.
그래서 알려진 단축 서비스 명단과의 대조로 판단한다.
  - 명단에 있으면: 오탐 없이 확정 탐지
  - 명단에 없는 신생 서비스는: 여기서는 놓치지만(미탐), 그 행동(다른 소유자로의
    리다이렉트)은 L2-H-01·02가 관측하므로 시스템 차원에서는 잡힌다.
이 기능의 고유 가치 = "목적지 은닉 도구를 썼다"는 의도 정보 + 숨겨진 진짜 목적지.

[L0과의 역할 분담]
L0은 접속 전에 원본 URL 문자열만 보고 판별하고, L2는 접속 후 여정 전체에서
단축 서비스 '경유'를 관측하며 resolved_url을 제공한다. 중복이 아닌 보완 관계.

네트워크 접속 없음 — L2-H-01의 Collector가 수집한 Raw Data를 재사용한다.
"""

from utils.http_parsing import etld1

# 알려진 URL 단축 서비스의 eTLD+1 명단.
# '지식 데이터'이므로 로직과 분리해 상수로 관리한다 — 명단이 늘어도 코드 수정 불필요,
# set이라 명단이 커져도 대조는 O(1). 확장·관리 주체는 팀 협의 대상 (L0 명단과 통합 제안 중).
SHORTENER_DOMAINS = {
    "bit.ly", "t.co", "goo.gl", "tinyurl.com", "is.gd", "buff.ly",
    "ow.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy",
    "han.gl", "vo.la", "url.kr",          # 국내 서비스
}


def analyze(raw: dict) -> dict:
    # 검사 대상 = 출발 URL + 각 hop의 목적지.
    #  - 출발 URL 포함 이유: 사용자가 받은 링크 자체가 단축 URL인 게 가장 흔한 패턴
    #  - 중간 목적지 포함 이유: 여정 중간에 단축 서비스를 끼워 추적을 세탁하는 패턴 대비
    urls = [raw["original_url"]] + [h["destination_url"] for h in raw["redirect_chain"]]

    # eTLD+1로 정규화해 대조 — api.bit.ly 같은 서브도메인 운용도 잡기 위함 (공용 유틸 사용)
    found = [(u, etld1(u)) for u in urls if etld1(u) in SHORTENER_DOMAINS]

    detected = len(found) > 0

    # resolved_url은 단축이 실제로 '풀린' 경우에만 기록한다.
    # 죽은 링크(삭제·만료·차단)는 리다이렉트가 없어서 final_url이 원본 그대로인데,
    # 그걸 resolved_url에 넣으면 "단축이 이 주소로 풀렸다"는 거짓 정보가 된다
    # → detected는 true(사용 자체는 관측), resolved_url은 null(풀린 목적지는 확인 못 함)
    resolved = raw["final_url"] if (detected and raw["redirect_chain"]) else None

    return {
        "id": "L2-H-04",
        "scanner": "header",
        "name": "url_shortener",
        "detected": detected,
        "evidence": {
            "shortener_domain": found[0][1] if detected else None,  # 첫 번째로 발견된 단축 도메인
            "resolved_url": resolved,
        },
    }
