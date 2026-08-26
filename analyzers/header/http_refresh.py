"""L2-H-08 HTTP Refresh Analyzer

[목적] Refresh 헤더를 이용한 '자동 페이지 이동 예약'을 관측한다.

[입력]  Raw Data의 headers.refresh, final_url(상대경로 절대화 기준), original_url
[출력]  Signal evidence{target_url, delay_seconds}

[이 기능이 감시하는 사각지대]
Refresh는 HTTP 공식 표준에 없는 레거시 헤더지만 브라우저들이 관습적으로 지원한다.
상태 코드 200(정상)을 유지한 채 이동을 예약하므로, 3xx만 추적하는 스캐너
(우리 Collector의 hop 루프 포함)에는 잡히지 않는다. 공격자가 리다이렉트 추적을
회피하는 우회로로 쓸 수 있어, 이 사각지대를 별도로 감시하는 것이 존재 이유다.
실측: Refresh 응답 URL에서 L2-H-01은 false(체인 없음), H-08만 true.

[detected 기준 = 헤더의 '존재 자체']
정상 사이트는 페이지 이동에 3xx(정식 방법)를 쓴다. 이 비표준 헤더는 정상 용법이
사실상 없으므로 존재만으로 관측 가치가 있다. (H-07과 기준이 다른 이유 —
그쪽은 inline이라는 정상 용법이 있어 값(attachment)을 기준으로 삼는다)

[파싱 원칙: 브라우저만큼 관대하게]
서버마다 표기가 제각각인데, 브라우저가 이해하는 표기를 스캐너가 못 읽으면
그 차이가 곧 회피 통로가 된다. 그래서 대소문자·공백·따옴표·콤마 구분자·소수 딜레이
전부 허용한다. (콤마: 브라우저는 "0,url=..." 도 따라간다 — 세미콜론만 보면 놓침)

네트워크 접속 없음 — L2-H-01의 Collector가 수집한 값을 재사용한다.
"""

import re
from urllib.parse import urljoin


def _parse_refresh(value: str) -> dict:
    """Refresh 헤더 값에서 딜레이(초)와 목적지 URL을 뽑는다.

    입력 예시 → 출력:
        "5; url=https://a.com"      → {"delay": 5,    "url": "https://a.com"}
        "0,url=http://evil/x"       → {"delay": 0,    "url": "http://evil/x"}   (콤마 구분)
        "5.5; URL='http://b.com'"   → {"delay": 5.5,  "url": "http://b.com"}    (소수·대문자·따옴표)
        "5"                         → {"delay": 5,    "url": None}              (자기 새로고침 예약)
        "abc; url=http://b.com"     → {"delay": None, "url": "http://b.com"}    (숫자 아님 → unknown)
    """
    delay = None
    url = None

    # 1) 구분자로 앞뒤 분리 — 세미콜론(표준적 관행)과 콤마(브라우저 허용) 둘 다 인정.
    #    maxsplit=1: url 값 안에 콤마가 또 있어도 첫 구분자에서만 자른다
    parts = re.split(r"[;,]", value, maxsplit=1)

    # 2) 앞부분 = 딜레이(초). 브라우저처럼 소수("5.5")도 허용하고,
    #    숫자가 아니면 억지로 0을 넣지 않고 None으로 남긴다 — "숫자로 확인 안 됨"은 unknown
    head = parts[0].strip()
    try:
        parsed_delay = float(head)
        # 5.0처럼 정수값이면 int로 (JSON 출력에서 5.0 대신 5)
        delay = int(parsed_delay) if parsed_delay.is_integer() else parsed_delay
    except ValueError:
        pass

    # 3) 뒷부분에서 url= 값 추출 — 대소문자(URL=)·등호 앞뒤 공백("url = ") 변형 허용
    if len(parts) > 1:
        match = re.match(r"url\s*=\s*(.*)", parts[1].strip(), re.IGNORECASE)
        if match:
            # 앞뒤 공백·따옴표 제거. 벗겼더니 빈 문자열이면 None (목적지 없음)
            url = match.group(1).strip().strip("'\"") or None

    return {"delay": delay, "url": url}


def analyze(raw: dict) -> dict:
    refresh_value = raw["headers"]["refresh"]

    if refresh_value is None:
        # Refresh 헤더 자체가 없음 = 미관측 (정상 사이트 대부분이 이 경우)
        return {
            "id": "L2-H-08",
            "scanner": "header",
            "name": "http_refresh",
            "detected": False,
            "evidence": {"target_url": None, "delay_seconds": None},
        }

    parsed = _parse_refresh(refresh_value)

    # 목적지가 상대 경로(url=/next)일 수 있으므로 절대 URL로 변환한다.
    # 기준(base)은 최종 도착 URL — 접속 실패로 null이면 원본 URL로 대체
    target = None
    if parsed["url"] is not None:
        base = raw["final_url"] or raw["original_url"]
        target = urljoin(base, parsed["url"])

    return {
        "id": "L2-H-08",
        "scanner": "header",
        "name": "http_refresh",
        # 헤더의 존재 자체가 관측 대상 (모듈 docstring 참고).
        # url= 없는 자기 새로고침 예약도 true + target_url null
        "detected": True,
        "evidence": {
            "target_url": target,
            "delay_seconds": parsed["delay"],
        },
    }
