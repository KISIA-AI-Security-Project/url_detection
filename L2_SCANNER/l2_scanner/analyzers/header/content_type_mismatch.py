"""L2-H-05 Content-Type 불일치 Analyzer

[목적] 서버가 선언한 콘텐츠 유형과 바디의 실제 유형이 다른지 확인한다.
       "HTML이라고 선언하고 실행파일을 준다" 같은 파일 위장 배포의 관측.

[입력]  Raw Data의 headers.content_type(서버의 주장),
        response_body.detected_type(libmagic이 앞부분 바이트에서 추정한 유형)
[출력]  Signal evidence{declared_type, detected_type}

[탐지 원리]
서버의 유형 선언과 libmagic의 접두부 분류 결과를 비교한다.
분류 결과는 추정이며 파일 전체 형식·실행 가능성·악성 여부를 검증하지 않는다.
부분 본문에서도 분류는 가능할 수 있지만, 그 결과의 범위는 읽은 바이트에 한정된다.

[비교 전 두 가지 보정]
1. unknown != 불일치: 한쪽이라도 확인 안 됐으면(null) 비교 자체가 불가 -> detected: null.
   "불일치를 관측했다"도 "일치를 확인했다"도 양쪽을 다 알아야 말할 수 있다. 
2. 동의어 보정(EQUIVALENT_PAIRS): libmagic은 JSON을 text/plain으로, HTML을 간혹
   text/xml로 읽는 등 선언 관행과 판독 결과가 어긋나는 정상 케이스가 있다.
   순진한 문자열 비교는 정상 사이트를 대량 오탐한다

네트워크 접속 없음 - L2-H-01의 Collector가 수집한 값을 재사용한다.
"""

from l2_scanner.config.knowledge import EQUIVALENT_PAIRS   # 동의어 쌍 - 지식 데이터는 config에서 관리
from l2_scanner.utils.http_parsing import split_mime

SIGNAL = {"id": "L2-H-05", "scanner": "header", "name": "content_type_mismatch"}


def _equivalent(declared: str, detected: str) -> bool:
    """두 유형이 같거나, 알려진 동의어 쌍이면 True. 쌍은 방향 무관하게 본다."""
    if declared == detected:
        return True
    return (declared, detected) in EQUIVALENT_PAIRS or (detected, declared) in EQUIVALENT_PAIRS


def analyze(raw: dict) -> dict:
    # 선언 유형: "text/html; charset=UTF-8" -> "text/html" (공용 유틸로 파라미터 제거, 소문자화)
    declared = split_mime(raw["headers"]["content_type"])
    # 실제 유형: Collector의 magic 판독 결과를 그대로 사용
    detected_type = raw["response_body"]["detected_type"]

    # 양쪽 다 확인된 경우에만 비교가 가능하다 (보정 1: 한쪽이라도 null이면 판정 불가)
    if declared is None or detected_type is None:
        mismatch = None
    else:
        mismatch = not _equivalent(declared, detected_type)   # 보정 2: 동의어 흡수

    return {
        **SIGNAL,
        "detected": mismatch,
        "evidence": {
            "declared_type": declared,        # 서버의 주장
            "detected_type": detected_type,   # 수집한 앞부분 바이트의 유형 추정
        },
    }
