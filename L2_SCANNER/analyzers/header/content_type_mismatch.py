"""L2-H-05 Content-Type 불일치 Analyzer

[목적] 서버가 '선언한' 콘텐츠 유형과 바디의 '실제' 유형이 다른지 확인한다.
       "HTML이라고 선언하고 실행파일을 준다" 같은 파일 위장 배포의 관측.

[입력]  Raw Data의 headers.content_type(서버의 주장),
        response_body.detected_type(magic bytes 판독 = 서버가 조작 못 하는 실체)
[출력]  Signal evidence{declared_type, detected_type}

[탐지 원리]
모든 파일 형식은 첫 바이트에 고유 서명(magic bytes)을 갖는다
(PNG=‰PNG, PDF=%PDF, exe=MZ...). 헤더는 서버가 마음대로 쓸 수 있지만
바이트 서명은 위조하면 파일이 동작하지 않으므로, 둘을 비교하면 거짓말이 드러난다.
판독은 Collector가 이미 해뒀고(바디가 잘려도 앞부분 서명은 유효), 여기서는 비교만 한다.

[비교 전 두 가지 보정]
1. unknown ≠ 불일치: 한쪽이라도 확인 안 됐으면(null) 비교 자체가 불가 → detected: false.
   "불일치를 관측했다"고 말하려면 양쪽을 다 알아야 한다.
2. 동의어 보정(EQUIVALENT_PAIRS): libmagic은 JSON을 text/plain으로, HTML을 간혹
   text/xml로 읽는 등 '선언 관행'과 '판독 결과'가 어긋나는 정상 케이스가 있다.
   순진한 문자열 비교는 정상 사이트를 대량 오탐한다

네트워크 접속 없음 — L2-H-01의 Collector가 수집한 값을 재사용한다.
"""

from utils.http_parsing import split_mime

# 실질적으로 같은 유형으로 취급할 쌍 — magic 판독 특성 보정.
# '지식 데이터'이므로 로직과 분리해 관리한다. 운영 중 정상 사이트에서 오탐이 나오면 여기에 쌍을 추가 (유지보수)
EQUIVALENT_PAIRS = {
    ("application/json", "text/plain"),   # magic은 JSON을 평문으로 읽는 경우가 많음
    ("text/html", "text/xml"),
    ("application/javascript", "text/plain"),
    ("text/css", "text/plain"),
}


def _equivalent(declared: str, detected: str) -> bool:
    """두 유형이 같거나, 알려진 동의어 쌍이면 True. 쌍은 방향 무관하게 본다."""
    if declared == detected:
        return True
    return (declared, detected) in EQUIVALENT_PAIRS or (detected, declared) in EQUIVALENT_PAIRS


def analyze(raw: dict) -> dict:
    # 선언 유형: "text/html; charset=UTF-8" → "text/html" (공용 유틸로 파라미터 제거, 소문자화)
    declared = split_mime(raw["headers"]["content_type"])
    # 실제 유형: Collector의 magic 판독 결과를 그대로 사용
    detected_type = raw["response_body"]["detected_type"]

    # 양쪽 다 확인된 경우에만 불일치를 관측 할 수 있다 (보정 1: unknown ≠ 불일치)
    mismatch = (
        declared is not None
        and detected_type is not None
        and not _equivalent(declared, detected_type)   # 보정 2: 동의어 흡수
    )

    return {
        "id": "L2-H-05",
        "scanner": "header",
        "name": "content_type_mismatch",
        "detected": mismatch,
        "evidence": {
            "declared_type": declared,        # 서버의 주장
            "detected_type": detected_type,   # 바이트 서명이 말하는 실체
        },
    }
