"""
그룹 D-2(오픈 리다이렉트) 판정에 쓰는 리다이렉트 파라미터 키 목록.

[선정 기준] 악성 URL 1,007,881건에서 "값이 실제로 외부 등록 도메인으로
해석되는" 쿼리 키를 집계해 관측된 것만 담았다. 주석의 건수가 그 관측치다.
관측 0건인 키(goto, redir, dest, destination, out, forward, success 등)는
넣지 않는다. 근거 없는 항목은 오탐만 늘린다.

[제외한 것]
view, ref, success는 리다이렉트와 무관한 용도로 훨씬 자주 쓰여 제외했다.

[매칭 방식]
키를 소문자로 정규화하고 'amp;' 접두어를 뗀 뒤 대조한다.
  - 정확히 일치하거나
  - 4자 이상 항목에 한해 부분 일치
부분 일치를 4자 이상으로 제한하는 이유는 'u' 같은 짧은 키 때문이다.
그대로 부분 일치를 허용하면 'user', 'uid', 'utm_source'가 전부 걸린다.
반면 returnUrl -> returnurl, RedirectUri -> redirecturi 같은 표기 변형은
부분 일치로 잡아야 한다.

'amp;' 접두어 처리가 필요한 이유는 HTML의 &amp;가 URL에 그대로 들어가는
경우가 실재하기 때문이다. amp;followup 98건, amp;continue 69건이 관측됐다.

[갱신 주기] 분기 1회. 코퍼스 재측정으로 신규 키를 보강한다.
"""

from __future__ import annotations

# 목록 버전 — analysis_record의 list_version에 실려 저장된다.
REDIRECT_KEYS_VERSION = "redirect_keys-2026-08"

REDIRECT_KEYS: frozenset[str] = frozenset({
    # --- 인증 흐름에서 쓰이는 키 (관측 상위) ---
    "continue",          # 840건 — Google 로그인
    "followup",          # 755건 — Google 로그인
    "redirect_uri",      # 642건 — OAuth 표준
    "openid.return_to",  # 594건 — OpenID
    "wreply",            #  61건 — WS-Federation
    "logout_uri",        #  32건
    # --- 범용 리다이렉트 키 ---
    "url",               # 398건
    "u",                 # 526건 — 짧아서 부분 일치 대상이 아니다
    "resource_url",      # 247건
    "next",              # 166건
    "redirect",          # 165건
    "returnurl",         # 142건
    "link",              #  70건
    "to",                #  53건 — 짧아서 부분 일치 대상이 아니다
    "ru",                #  32건 — 짧아서 부분 일치 대상이 아니다
    # --- 관측되지는 않았으나 위 항목의 표기 변형으로 흔한 것 ---
    #     부분 일치가 잡아주지만 명시해 두면 목록만 보고도 의도가 읽힌다.
    "redirect_url",
    "return_url",
    "return_to",
    "callback",
    "target",
})

# 부분 일치를 허용할 최소 길이. 위 docstring의 'u' 사례 참고.
REDIRECT_KEY_MIN_PARTIAL_LENGTH = 4
