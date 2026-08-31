"""
그룹 D-1(XSS) 판정에 쓰는 주입 시그니처.

[SQLi를 넣지 않는 이유]
XSS와 SQLi는 피해 대상이 다르다.

    구분        | SQLi                      | Reflected XSS
    ----------- | ------------------------- | ----------------------------
    피해 대상   | 서버(DB)                  | URL을 클릭한 사람
    URL의 역할  | 공격자가 서버에 쏘는 요청 | 피해자에게 보내는 미끼
    발견 위치   | 웹서버 접근 로그, WAF     | 메일·문자로 유입된 링크

SQLi는 공격자가 직접 ?id=1 OR 1=1 을 보내므로 메일로 유통되지 않는다. 본 시스템의
입력원은 메일 등에서 유입되는 URL이고 웹서버 접근 로그는 분석 대상이 아니다.
악성 URL 1,007,881건 관측 결과 SQLi 시그니처 0건이 이를 확인한다.

[정규식 작성 규칙]
측정 중 실제로 발생한 오탐이 근거다.
  패턴 (--\\s|#|/\\*)\\s*$  ->  /api/netflix_telegram_sms/net/*   (경로 와일드카드)
                               /images/gallery/ca-en/*
아래 세 규칙을 지킨다.
  1. 단어 경계를 준다. 없으면 무관한 단어 안쪽이 걸린다.
  2. URL 문법과 겹치는 기호는 단독으로 쓰지 않는다.
     '#'은 프래그먼트 구분자, '/*'는 경로에 흔하다.
  3. 공백 우회를 고려한다.

[순서] 관측 빈도가 높은 것을 앞에 둔다. 목록 순서대로 검사하고 처음 걸린 것을 채택한다.

[근거] 악성 URL 1,007,881건 분석. 주석의 건수는 그 관측치다.

[갱신 주기] 분기 1회. 새 우회 기법은 정규식으로 잡히지 않으므로 코퍼스 재측정으로 보강한다.
"""

from __future__ import annotations

import re

# 목록 버전 — analysis_record의 list_version에 실려 저장된다.
INJECTION_PATTERNS_VERSION = "injection_patterns-2026-08"

# (detection_type, 정규식)
# 모듈 로드 시 1회만 컴파일한다. 요청마다 컴파일할 이유가 없다.
_RAW_PATTERNS: tuple[tuple[str, str], ...] = (
    (
        # "이런 이벤트가 생기면 이 코드를 실행해라" — onerror(로딩 실패 시),
        # onmouseover(마우스 올릴 때) 등.
        #
        # 관측 118건으로 최다다. <script>(24건)보다 많은 이유는 필터가 script를
        # 막으니 이미지 태그와 이벤트 핸들러로 우회하기 때문이다.
        # 실제 형태: ?Search="/><img src=x onerror=alert(1)>
        #
        # 앞에 공백·따옴표·슬래시가 오는 것을 요구한다. 그냥 \bon\w+= 로 두면
        # ?button=on 같은 정상 값이 걸린다.
        "EVENT_HANDLER",
        r"""[\s"'/]on(?:error|load|focus|blur|mouseover|mouseout|click|"""
        r"""toggle|animationstart|beforescriptexecute)\s*=""",
    ),
    (
        # 실행 능력이 있는 HTML 태그 자체를 주입한다.
        # '<' 뒤 공백을 허용하는 이유는 "<  script" 우회가 실재하기 때문이다.
        "TAG_INJECTION",
        r"<\s*/?\s*(?:script|iframe|svg|img|object|embed|body|details|marquee)\b",
    ),
    (
        # 스킴 자리에 코드를 실행시키는 가짜 스킴을 주입한다.
        # 스킴 자체가 javascript:인 경우는 F-1이 다룬다. 여기는 파라미터 값 안이다.
        #
        # data:text/html 뒤에 [;,]를 요구한다. 실제 데이터 URI는 반드시
        # data:text/html;base64,... 또는 data:text/html,<script> 형태다.
        # 요구하지 않으면 ?user=&_verify?service=mail&data:text/html 같은
        # 파라미터 이름이 걸린다. 실측에서 10건이 이 형태의 오탐이었다.
        "PSEUDO_PROTOCOL",
        r"(?:javascript|vbscript)\s*:|data\s*:\s*text/html\s*[;,]",
    ),
)

INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (detection_type, re.compile(pattern, re.IGNORECASE | re.DOTALL))
    for detection_type, pattern in _RAW_PATTERNS
)

# 퍼센트 디코딩 상한.
#
# (1) 상한이 없으면 자기 재생성 입력에서 무한 루프에 빠질 수 있고,
#     URL당 반복 비용이 100만 건 규모에서 성능에 부담이 된다.
# (2) 코퍼스 실측상 4회 이상 인코딩된 악성 URL은 0건이며 3회도 21건(0.002%)에
#     불과하다. 3은 임의값이 아니라 관측된 최대치다.
#
# 실측 분포: 0회 97.812% / 1회 2.177% / 2회 0.009% / 3회 0.002%
MAX_DECODE_DEPTH = 3
