"""
그룹 F — 기타

F-1 비표준 프로토콜

모든 판정은 0단계(parsing.py)가 만든 ParseResult만 입력으로 받으며,
외부 접속을 일절 하지 않는다.
"""

from __future__ import annotations

import logging

from l0.common import GROUP_F_NONSTANDARD_SCHEME
from l0.models import AnalysisRecord, detected, not_applicable
from l0.parsing import ParseResult

logger = logging.getLogger(__name__)

# 웹 표준 프로토콜.
#
# ws/wss는 넣지 않는다. A-4(비표준 포트)가 ws/wss를 웹 스킴으로 취급하는 것과
# 다른데, 묻는 질문이 다르기 때문이다.
#   A-4 : "이 웹 스킴의 기본 포트가 맞는가"  -> ws/wss도 웹이므로 판정 대상
#   F-1 : "브라우저 주소창에 넣어 열리는가"  -> ws/wss는 열리지 않는다
# ws://는 페이지 안의 JavaScript가 여는 연결이지 사용자가 클릭해 이동하는
# 주소가 아니다. 메일 본문의 링크가 ws://라면 그 자체로 이상 신호다.
SCHEME_WHITE = frozenset({"http", "https"})


# ---------------------------------------------------------------------------
# F-1. 비표준 프로토콜
# ---------------------------------------------------------------------------
def check_nonstandard_scheme(result: ParseResult) -> AnalysisRecord:
    """
    웹 표준이 아닌 프로토콜을 쓰는지 판정한다.

    유입된 URL이 http/https가 아니라는 것은 그 자체로 이상 신호다. 무엇을
    노리는지는 스킴마다 다르다.

        javascript:  클릭 즉시 현재 페이지 맥락에서 코드가 실행된다
        data:        페이지 내용을 URL 안에 통째로 담는다. 서버가 없어도 된다
        file:        로컬 파일이나 UNC 경로(\\\\attacker\\share)를 연다
        ftp:         Chrome 95(2021)에서 지원이 제거됐다. 열리지 않는다
        ssh telnet   외부 프로그램을 띄우는 스킴. 웹 링크로 올 이유가 없다
        smb rdp      〃

    [무엇을 판정하지 않는가]
    포트가 몇 번인지는 보지 않는다. 그것은 A-4의 몫이다. 여기서는 "웹이
    아니다"라는 사실만 본다. 그래서 ftp://a.com:8021 은 F-1(비웹 스킴)에만
    걸리고 A-4에는 걸리지 않는다.

    [파싱을 통과한 것만 온다]
    스킴이 아예 없거나(notaurl) 형식이 깨진 문자열은 0단계에서 FAILURE로
    걸러져 여기 도달하지 않는다.
    """
    name = GROUP_F_NONSTANDARD_SCHEME
    parsed = result.parsed

    if parsed is None:
        return not_applicable(name)

    # ada는 protocol을 "https:" 처럼 콜론을 붙여 돌려준다.
    scheme = parsed.protocol.rstrip(":").lower()
    if not scheme:
        return not_applicable(name)

    if scheme in SCHEME_WHITE:
        return not_applicable(name)

    # value를 문자열이 아니라 dict로 둔다. 나중에 필드를 늘릴 때
    # 소비자 쪽을 깨뜨리지 않기 위함이며, 다른 판정들과 형식도 맞는다.
    return detected(name, {"scheme": scheme})


# registry가 순차 실행할 때 참조하는 목록.
# 각 함수는 ParseResult 하나만 받고 AnalysisRecord 하나를 돌려주는 동일한 형태다.
GROUP_F_DETECTORS = (check_nonstandard_scheme,)
