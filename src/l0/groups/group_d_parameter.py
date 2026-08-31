"""
그룹 D — 파라미터 분석

D-1 XSS / D-2 오픈 리다이렉트

모든 판정은 0단계(parsing.py)가 만든 ParseResult만 입력으로 받으며,
서버 응답을 확인하거나 리다이렉트를 따라가지 않는다.
"""

from __future__ import annotations

import logging
from typing import Iterator
from urllib.parse import unquote

from ada_url import URL

from l0.common import GROUP_D_OPEN_REDIRECT, GROUP_D_XSS
from l0.models import AnalysisRecord, detected, not_applicable
from l0.parsing import ParseResult, _tldextract
from l0.data.injection_patterns import (
    INJECTION_PATTERNS,
    INJECTION_PATTERNS_VERSION,
    MAX_DECODE_DEPTH,
)
from l0.data.redirect_keys import (
    REDIRECT_KEYS,
    REDIRECT_KEYS_VERSION,
    REDIRECT_KEY_MIN_PARTIAL_LENGTH,
)

logger = logging.getLogger(__name__)

_LOCATION_PATH = "PATH"
_LOCATION_QUERY = "QUERY"
_LOCATION_FRAGMENT = "FRAGMENT"

# D-2: 키가 목록에 없어도 값이 이 문자를 포함하면 목적지 해석을 시도한다.
# '//'는 스킴 상대 URL, ':'는 스킴, '\'는 백슬래시 우회(/\evil.com)를 잡는다.
# 값 전체가 아니라 앞부분만 보는 이유는 정상 값 안쪽의 콜론(타임스탬프 등)까지
# 걸려 불필요한 파싱이 늘어나기 때문이다.
_URL_LIKE_MARKERS = ("//", "\\", ":")
_URL_LIKE_PREFIX_LENGTH = 16


# ---------------------------------------------------------------------------
# D-1. XSS
# ---------------------------------------------------------------------------
def check_xss(result: ParseResult) -> AnalysisRecord:
    """
    URL에 스크립트 실행을 노린 주입 페이로드가 있는지 판정한다.

    [무엇을 말하는 판정인가]
    서버 응답을 보지 않으므로 주입이 실제로 성공하는지는 판단하지 않는다.
    서버가 페이로드를 이스케이프하면 아무 일도 일어나지 않는다. L0는
    "페이로드가 존재한다"까지만 말한다.

    [SQLi를 다루지 않는 이유]
    SQLi는 공격자가 서버에 직접 쏘는 요청이라 메일로 유통되지 않는다. 본
    시스템의 입력원은 메일 등에서 유입되는 URL이고 웹서버 접근 로그는 분석
    대상이 아니다. 악성 URL 100만 건 관측 0건이 이를 확인한다.
    자세한 근거는 data/injection_patterns.py 참고.

    [프래그먼트를 검사하는 이유]
    DOM 기반 XSS는 '#' 뒤에 페이로드를 둔다. 프래그먼트는 서버로 전송되지
    않아 서버 로그와 WAF에 남지 않는다. URL 문자열을 보는 L0가 잡을 수 있는
    유일한 지점이다.
    """
    name = GROUP_D_XSS
    parsed = result.parsed
    list_version = {"injection_patterns": INJECTION_PATTERNS_VERSION}

    if parsed is None:
        return not_applicable(name, list_version=list_version)

    # 경로·쿼리·프래그먼트를 합치지 않고 따로 본다.
    # '?'와 '#'은 구조적 구분자라 페이로드가 그 경계를 넘어 성립할 수 없고,
    # 특히 프래그먼트는 서버로 전송조차 되지 않는다. 나눠 보면 매칭 위치가
    # 그대로 location이 된다.
    for location, raw in (
        (_LOCATION_PATH, parsed.pathname),
        (_LOCATION_QUERY, parsed.search),
        (_LOCATION_FRAGMENT, parsed.hash),
    ):
        if not raw:
            continue

        decoded = _decode_repeatedly(raw)

        for detection_type, pattern in INJECTION_PATTERNS:
            match = pattern.search(decoded)
            if match is None:
                continue

            return detected(
                name,
                {
                    "detection_type": detection_type,
                    "matched_string": match.group(0),
                    "location": location,
                },
                list_version=list_version,
            )

    return not_applicable(name, list_version=list_version)


def _decode_repeatedly(text: str) -> str:
    """
    변화가 없을 때까지 퍼센트 디코딩한다. 상한은 MAX_DECODE_DEPTH다.

    상한이 필요한 이유는 두 가지다. 자기 재생성 입력에서 무한 루프에 빠질 수
    있고, URL당 반복 비용이 100만 건 규모에서 성능에 부담이 된다.
    """
    for _ in range(MAX_DECODE_DEPTH):
        decoded = unquote(text)
        if decoded == text:
            break
        text = decoded
    return text


# ---------------------------------------------------------------------------
# D-2. 오픈 리다이렉트
# ---------------------------------------------------------------------------
def check_open_redirect(result: ParseResult) -> AnalysisRecord:
    """
    정상 도메인의 리다이렉트 기능으로 외부 도메인에 유도하는지 판정한다.

    [확인함이 곧 악성은 아니다]
    코퍼스 관측 1위 continue=https://accounts.google.com/... 은 구글 로그인의
    정상 파라미터이고 redirect_uri는 OAuth 표준이다. L0는 목적지가 악성인지
    알 수 없으므로 "외부로 나간다"는 사실만 기록한다.

    대신 target_domain을 남기는 데 실질적 가치가 있다. 종합 단계가 이 값을
    A·B 판정에 다시 태우면 목적지가 paypa1.com일 때 B-2가 잡아 준다.

    [값을 파서로 해석하는 이유]
    접두사 매칭(http://, //로 시작하는가)은 우회가 쉽다. ada에 base를 주면
    브라우저와 동일한 목적지가 나온다.
        //evil.com/x               -> evil.com
        /\\evil.com                 -> evil.com   (백슬래시 우회)
        https://legit.com@evil.com -> evil.com   (userinfo 트릭)
        ///evil.com                -> evil.com
    특히 @ 트릭은 정규식으로 도메인을 뽑으면 정반대 결론이 나온다.
    쿼리 값 내부의 백슬래시는 0단계 파서가 건드리지 않으므로 여기서 처리한다.
    """
    name = GROUP_D_OPEN_REDIRECT
    parsed = result.parsed
    extracted = result.extracted
    list_version = {"redirect_keys": REDIRECT_KEYS_VERSION}

    # 원본과 비교할 기준이 없으면 판정할 수 없다.
    if parsed is None or extracted is None or not extracted.registered_domain:
        return not_applicable(name, list_version=list_version)

    source_domain = extracted.registered_domain.lower()

    for key, value in _iter_query_items(result):
        if not _is_redirect_candidate(key, value):
            continue

        try:
            target = URL(value, base=parsed.href)
        except (ValueError, TypeError):
            # 목적지로 해석되지 않는 값이다. 판정 대상이 아니다.
            continue

        target_host = target.hostname.lower()
        if not target_host:
            continue

        record = {
            "matched_key": key,
            "raw_value": value,
            "target_host": target_host,
            "source_domain": source_domain,
        }

        # IP로 보내는 리다이렉트는 등록 도메인이 없지만 위험하다.
        if target.host_type.name in ("IPV4", "IPV6"):
            return detected(
                name,
                {**record, "target_domain": "", "detection_type": "IP_TARGET"},
                list_version=list_version,
            )

        target_domain = _tldextract(target_host).top_domain_under_public_suffix.lower()
        # //a 처럼 TLD가 없는 문자열은 목적지로 성립하지 않는다.
        if not target_domain:
            continue
        # login.site.com -> www.site.com 같은 같은 서비스 내 이동은 정상이다.
        # hostname이 아니라 registered_domain으로 비교하는 이유가 이것이다.
        if target_domain == source_domain:
            continue

        return detected(
            name,
            {
                **record,
                "target_domain": target_domain,
                "detection_type": "EXTERNAL_DOMAIN",
            },
            list_version=list_version,
        )

    return not_applicable(name, list_version=list_version)


def _iter_query_items(result: ParseResult) -> Iterator[tuple[str, str]]:
    """쿼리의 (키, 값)을 순서대로 내놓는다.

    result.query는 0단계에서 parse_search_params가 만든 것이며 값이 이미
    디코드돼 있다. urllib.parse.parse_qs를 쓰지 않는다 — 레거시 파서라
    WHATWG와 동작이 다르고, 같은 일을 두 번 할 이유도 없다.
    """
    for key, values in result.query.items():
        for value in values:
            if value:
                yield key, value


def _is_redirect_candidate(key: str, value: str) -> bool:
    """이 파라미터의 목적지를 해석해 볼 가치가 있는지 판단한다."""
    if _matches_redirect_key(key):
        return True
    # 키가 목록에 없어도 값이 URL처럼 보이면 본다.
    # 목록에 없는 키로 리다이렉트하는 경우를 놓치지 않기 위함이다.
    prefix = value[:_URL_LIKE_PREFIX_LENGTH]
    return any(marker in prefix for marker in _URL_LIKE_MARKERS)


def _matches_redirect_key(key: str) -> bool:
    """
    키를 정규화해 REDIRECT_KEYS와 대조한다.

    'amp;' 접두어를 떼는 이유는 HTML의 &amp;가 URL에 그대로 들어가는 경우가
    실재하기 때문이다(amp;followup 98건, amp;continue 69건 관측).

    부분 일치를 4자 이상 항목으로 제한하는 이유는 'u' 같은 짧은 키 때문이다.
    제한이 없으면 user, uid, utm_source가 전부 걸린다. 반면 returnUrl,
    RedirectUri 같은 표기 변형은 부분 일치로 잡아야 한다.
    """
    normalized = key.lower()
    if normalized.startswith("amp;"):
        normalized = normalized[4:]

    if normalized in REDIRECT_KEYS:
        return True

    return any(
        candidate in normalized
        for candidate in REDIRECT_KEYS
        if len(candidate) >= REDIRECT_KEY_MIN_PARTIAL_LENGTH
    )


# registry가 순차 실행할 때 참조하는 목록.
# 각 함수는 ParseResult 하나만 받고 AnalysisRecord 하나를 돌려주는 동일한 형태다.
GROUP_D_DETECTORS = (
    check_xss,
    check_open_redirect,
)
