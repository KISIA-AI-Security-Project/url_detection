"""
그룹 E — 문자열 구조 이상 탐지

E-1 DGA 패턴 의심 / E-2 긴 URL / E-3 Base64 인코딩
E-4 접속 호스트 교란 / E-5 서브도메인 구조 이상

모든 판정은 0단계(parsing.py)가 만든 ParseResult만 입력으로 받으며,
외부 접속을 일절 하지 않는다.
"""

from __future__ import annotations

import base64
import binascii
import logging
import math
import re
from collections import Counter

from l0.common import (
    GROUP_E_BASE64,
    GROUP_E_DGA_PATTERN,
    GROUP_E_HOST_SPOOFING,
    GROUP_E_LONG_URL,
    GROUP_E_SUBDOMAIN_ANOMALY,
)
from l0.models import AnalysisRecord, detected, not_applicable
from l0.parsing import ParseResult, _tldextract

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# E-1: DGA 판정 상수
# ---------------------------------------------------------------------------
# 이보다 짧은 도메인은 판정하지 않는다. 표본이 적어 엔트로피가 심하게 왜곡된다.
# 예를 들어 4자 도메인은 모든 글자가 달라도 엔트로피가 2.0에 그친다.
_DGA_MIN_DOMAIN_LENGTH = 8

# 섀넌 엔트로피 임계. 글자가 고르게 흩어져 있을수록 값이 커진다.
# 사람이 지은 이름은 특정 글자가 반복되어 엔트로피가 낮다.
_DGA_ENTROPY_THRESHOLD = 3.8

# 모음 비율. 사람이 읽을 수 있는 단어는 모음이 30~45% 안팎이다.
# 양쪽 극단을 모두 본다 — 자음만 늘어놓은 것도, 모음만 늘어놓은 것도 부자연스럽다.
_DGA_VOWEL_RATIO_LOW = 0.15
_DGA_VOWEL_RATIO_HIGH = 0.70

# 연속 자음 개수. 영어에서 자음이 5개 이상 끊기지 않고 이어지는 단어는 거의 없다.
_DGA_MAX_CONSECUTIVE_CONSONANTS = 5

_VOWELS = frozenset("aeiou")

# ---------------------------------------------------------------------------
# E-2: 길이 임계
# ---------------------------------------------------------------------------
_LONG_URL_TOTAL = 120
_LONG_URL_PATH = 60
_LONG_URL_QUERY = 80

# ---------------------------------------------------------------------------
# E-3: Base64 판정 상수
# ---------------------------------------------------------------------------
# 이보다 짧은 값은 검사하지 않는다. 일반 영단어나 짧은 식별자가
# 우연히 Base64 문자 집합을 만족해 대량 오탐이 난다.
_BASE64_MIN_LENGTH = 16

# 표준 Base64와 URL-Safe Base64를 함께 받는다.
# 표준은 +/ 를, URL-Safe는 -_ 를 쓴다. 패딩(=)은 뒤에서 보정하므로 선택으로 둔다.
_BASE64_CHARSET = re.compile(r"^[A-Za-z0-9+/\-_]+={0,2}$")

# 디코딩 결과가 "의미 있는 평문"인지 가르는 표시.
# 단순히 디코딩에 성공했다는 것만으로는 부족하다. 임의의 문자열도 운 좋게
# 디코딩되는 경우가 있어, 평문 안에 실제로 쓸모 있는 내용이 있는지 본다.
_BASE64_PAYLOAD_MARKERS = re.compile(
    r"://|@|<\s*script|javascript\s*:|\b(?:cmd|powershell|/bin/sh|wget|curl)\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# E-5: 서브도메인 구조 상수
# ---------------------------------------------------------------------------
# 깊이 임계를 4로 둔다. 3이 아니다.
#
# s3.dualstack.us-east-1.amazonaws.com 처럼 정상 인프라가 깊이 3을 쓰는 경우가
# 흔해, 3을 기준으로 삼으면 AWS·CDN 계열이 대량 오탐된다. 깊이만으로는 판별력이
# 약하므로 임계를 한 단계 올리고, 깊이 자체는 탐지 여부와 무관하게 value에
# 관찰 사실로 남겨 종합 단계가 참고할 수 있게 한다.
_SUBDOMAIN_DEPTH_THRESHOLD = 4

# 서브도메인 라벨에 TLD가 끼어 있는지 검사할 때 쓰는 집합.
#
# AWS Route53의 "등록 가능 TLD 목록"은 쓰지 않는다. 그것은 "AWS에서 살 수 있는
# TLD"이지 "정상 TLD"가 아니며, .xyz .top 같은 피싱 빈발 TLD도 포함되고 AWS가
# 취급하지 않는 정상 국가 TLD는 누락된다(CLAUDE.md 폐기 설계 메모 참고).
#
# 대신 0단계가 이미 들고 있는 PSL 스냅샷을 그대로 쓴다. 같은 목록으로
# 판정해야 "우리 파서가 보는 TLD"와 "우리가 TLD로 세는 것"이 어긋나지 않는다.
_PSL_SUFFIXES: frozenset[str] = frozenset(_tldextract.tlds)


# ---------------------------------------------------------------------------
# E-1. DGA 패턴 의심
# ---------------------------------------------------------------------------
def check_dga_pattern(result: ParseResult) -> AnalysisRecord:
    """
    도메인 라벨이 알고리즘으로 생성된 것처럼 보이는지 판정한다.

    DGA(Domain Generation Algorithm)는 악성코드가 C2 서버 주소를 매일 새로
    만들어 내는 기법이다. 차단 목록이 따라잡기 전에 도메인을 갈아치우는 것이
    목적이라 사람이 읽을 수 없는 무작위 문자열이 된다.

    사람이 지은 이름과 기계가 만든 문자열은 세 가지 통계로 갈린다.
      1. 섀넌 엔트로피 — 글자가 고르게 흩어져 있는가
      2. 모음 비율    — 읽을 수 있는 단어는 모음이 30~45% 안팎이다
      3. 연속 자음    — 영어에서 자음 5개가 끊기지 않고 이어지는 일은 드물다

    [검사 대상에서 빼는 것]
    8자 미만은 표본이 적어 엔트로피가 심하게 왜곡된다. 숫자로만 이루어진
    도메인은 모음·자음이라는 개념 자체가 성립하지 않는다.
    """
    name = GROUP_E_DGA_PATTERN
    extracted = result.extracted

    if extracted is None or not extracted.domain:
        return not_applicable(name)

    domain = extracted.domain.lower()

    if len(domain) < _DGA_MIN_DOMAIN_LENGTH or domain.isdigit():
        return not_applicable(name)

    entropy = _shannon_entropy(domain)
    vowel_ratio = _vowel_ratio(domain)
    max_consecutive = _max_consecutive_consonants(domain)

    observation = {
        "domain": domain,
        "shannon_entropy": round(entropy, 2),
        "vowel_ratio": round(vowel_ratio, 2),
        "max_consec_consonants": max_consecutive,
    }

    # 유형 1 — 엔트로피가 높으면서 모음 비율이 양극단에 있다.
    # 두 조건을 함께 걸어야 한다. 엔트로피만 보면 정상 긴 도메인이 걸리고,
    # 모음 비율만 보면 짧은 약어가 걸린다.
    if entropy >= _DGA_ENTROPY_THRESHOLD and (
        vowel_ratio < _DGA_VOWEL_RATIO_LOW or vowel_ratio > _DGA_VOWEL_RATIO_HIGH
    ):
        return detected(name, {**observation, "detection_type": "ENTROPY_VOWEL"})

    # 유형 2 — 자음이 지나치게 길게 이어진다. 엔트로피와 무관하게 성립한다.
    if max_consecutive >= _DGA_MAX_CONSECUTIVE_CONSONANTS:
        return detected(
            name, {**observation, "detection_type": "CONSECUTIVE_CONSONANT"}
        )

    # 미탐지여도 계산한 지표는 남긴다. 판정을 수행했다는 사실 자체가 증거이고,
    # 임계값을 나중에 재조정할 때 근거가 된다.
    return not_applicable(name, value=observation)


def _shannon_entropy(text: str) -> float:
    """
    섀넌 엔트로피를 계산한다.

    각 글자가 나올 확률 p에 대해 -sum(p * log2(p))다. 글자가 고르게 흩어져
    있을수록 커지고, 같은 글자가 반복될수록 작아진다.
    """
    if not text:
        return 0.0

    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in Counter(text).values()
    )


def _vowel_ratio(text: str) -> float:
    """전체 글자 수 대비 모음 비율. 알파벳이 하나도 없으면 0.0."""
    letters = [ch for ch in text if ch.isalpha()]
    if not letters:
        return 0.0
    return sum(1 for ch in letters if ch in _VOWELS) / len(letters)


def _max_consecutive_consonants(text: str) -> int:
    """
    발음할 수 없는 구간이 끊기지 않고 이어지는 최대 길이.

    모음에서만 끊고 숫자에서는 끊지 않는다. 이 지표가 재려는 것은 "사람이
    소리 내어 읽을 수 있는가"인데, 숫자는 그 흐름을 이어 주지 않고 오히려
    더 읽기 어렵게 만든다. xjq87zpk91bwc 같은 DGA 도메인은 숫자를 중간에
    섞어 자음 구간을 끊는 것처럼 보이게 하는데, 숫자에서 끊어 세면 이 도메인의
    최대 연속이 3에 그쳐 탐지되지 않는다. 숫자를 포함해 세면 13이다.

    하이픈에서는 끊는다. secure-login-verify 처럼 정상 도메인이 하이픈으로
    단어를 잇는 형태가 흔하고, 하이픈은 사람이 읽을 때 실제로 끊어 읽는다.
    """
    longest = 0
    current = 0
    for ch in text:
        if ch in _VOWELS or not ch.isalnum():
            current = 0
            continue
        current += 1
        longest = max(longest, current)
    return longest


# ---------------------------------------------------------------------------
# E-2. 긴 URL
# ---------------------------------------------------------------------------
def check_long_url(result: ParseResult) -> AnalysisRecord:
    """
    URL이 비정상적으로 긴지 판정한다.

    긴 URL은 그 자체로 악성은 아니지만, 사용자가 주소를 끝까지 읽지 못하게
    만들어 실제 도착지를 가리는 데 쓰인다. 인코딩된 페이로드나 리다이렉트
    체인을 담느라 길어지는 경우도 많다.

    세 축을 따로 재는 이유는 어디가 길어졌는지가 의미를 갖기 때문이다.
    경로가 길면 디렉터리 위장, 쿼리가 길면 페이로드 은닉인 경우가 많다.

    [유형을 배열로 남기는 이유]
    셋이 동시에 걸릴 수 있고, 어느 축이 길어졌는지가 그대로 증거다.
    하나만 골라 버리면 정보가 사라진다.
    """
    name = GROUP_E_LONG_URL
    parsed = result.parsed

    if parsed is None:
        return not_applicable(name)

    # 원본 URL이 아니라 파서가 정규화한 href를 잰다.
    # 원본은 앞뒤 공백이나 표기 차이로 길이가 흔들린다.
    total_length = len(parsed.href)
    path_length = len(parsed.pathname)
    query_length = len(parsed.search)

    observation = {
        "total_length": total_length,
        "path_length": path_length,
        "query_length": query_length,
    }

    detection_type = []
    if total_length >= _LONG_URL_TOTAL:
        detection_type.append("TOTAL_LENGTH")
    if path_length >= _LONG_URL_PATH:
        detection_type.append("PATH_LENGTH")
    if query_length >= _LONG_URL_QUERY:
        detection_type.append("QUERY_LENGTH")

    if detection_type:
        return detected(name, {"detection_type": detection_type, **observation})

    # 미탐지여도 측정한 길이는 남긴다.
    return not_applicable(name, value=observation)


# ---------------------------------------------------------------------------
# E-3. Base64 인코딩
# ---------------------------------------------------------------------------
def check_base64(result: ParseResult) -> AnalysisRecord:
    """
    쿼리 파라미터 값에 Base64로 감춘 페이로드가 있는지 판정한다.

    공격자가 목적지 URL이나 피해자 식별자를 Base64로 감싸면 문자열 검사가
    통째로 무력화된다. 풀어 보면 안에 URL이나 메일 주소가 들어 있다.

    [단순히 디코딩되는 것만으로는 부족하다]
    임의의 문자열도 운 좋게 Base64로 디코딩되는 경우가 있다. 그래서 평문 안에
    실제로 쓸모 있는 내용(URL, 메일 주소, 스크립트·명령어)이 있는지까지 본다.

    [표준과 URL-Safe를 모두 시도하는 이유]
    표준 Base64는 +/ 를 쓰는데 이 두 글자는 URL에서 다른 뜻을 갖는다. 그래서
    URL에 실을 때는 -_ 로 바꾼 URL-Safe 변형을 쓰는 것이 보통이다. 어느 쪽이
    들어올지 알 수 없으므로 URL-Safe를 먼저 시도하고 실패하면 표준으로 간다.
    """
    name = GROUP_E_BASE64

    if result.parsed is None:
        return not_applicable(name)

    payloads = []
    # result.query는 0단계에서 parse_search_params가 만든 것이며 값이 이미
    # 디코드돼 있다. urllib.parse.parse_qs를 쓰지 않는다 — 레거시 파서라
    # WHATWG와 동작이 다르고, 같은 일을 두 번 할 이유도 없다.
    for key, values in result.query.items():
        for value in values:
            decoded = _try_decode_base64(value)
            if decoded is None:
                continue
            if not _BASE64_PAYLOAD_MARKERS.search(decoded):
                continue
            payloads.append(
                {
                    "parameter_name": key,
                    "encoded_value": value,
                    "decoded_content": decoded,
                }
            )

    if not payloads:
        return not_applicable(name)

    # 하나만 고르지 않고 전부 남긴다. 파라미터마다 다른 것을 숨길 수 있고
    # (목적지 URL과 피해자 식별자를 따로 싣는 형태가 흔하다), 각각이 독립된
    # 증거이므로 후속 단계가 모두 볼 수 있어야 한다.
    return detected(name, {"payloads": payloads})


def _try_decode_base64(value: str) -> str | None:
    """
    Base64로 보이면 풀어서 평문을 돌려준다. 아니면 None.

    패딩을 보정하는 이유는 URL에 실을 때 '='를 떼는 경우가 많기 때문이다.
    Base64는 4의 배수 길이여야 하므로 모자란 만큼 채워 준다.
    """
    if len(value) < _BASE64_MIN_LENGTH:
        return None
    if not _BASE64_CHARSET.match(value):
        return None

    padded = value + "=" * (-len(value) % 4)

    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            raw = decoder(padded)
        except (binascii.Error, ValueError):
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        # 제어 문자가 섞여 있으면 사람이 읽는 평문이 아니다.
        # 우연히 디코딩된 이진 쓰레기를 걸러 낸다.
        if text and text.isprintable():
            return text

    return None


# ---------------------------------------------------------------------------
# E-4. 접속 호스트 교란
# ---------------------------------------------------------------------------
def check_host_spoofing(result: ParseResult) -> AnalysisRecord:
    """
    userinfo(@ 앞부분)에 정상 도메인을 넣어 실제 접속처를 가리는지 판정한다.

        https://www.google.com@attacker-portal.net/auth
                ^^^^^^^^^^^^^^ 사람이 읽는 부분     ^^^^^^^^^^^^^^^^^^^ 실제 접속처

    브라우저는 @ 앞을 사용자 계정 정보로 처리하고 @ 뒤로 접속한다. 사람은 왼쪽
    부터 읽으므로 구글로 착각한다.

    [파서가 이미 해결해 준 것]
    다중 @(https://a@b@evil.com)의 파싱 모호성은 0단계의 WHATWG 파서가
    처리한다. 여기서는 username과 hostname만 보면 된다. 직접 문자열을 쪼개
    판정하면 브라우저와 다른 결론이 나온다.
    """
    name = GROUP_E_HOST_SPOOFING
    parsed = result.parsed

    if parsed is None:
        return not_applicable(name)

    # ada는 userinfo가 없으면 빈 문자열을 돌려준다. None이 아니다.
    if not parsed.username:
        return not_applicable(name)

    return detected(
        name,
        {
            "spoofed_host": parsed.username,
            "actual_dst_host": parsed.hostname,
            # 비밀번호 자리까지 쓴 경우가 있다. 값 자체는 남기지 않고
            # 존재 여부만 기록한다 — 자격증명이 레코드에 실리면 안 된다.
            "has_password": bool(parsed.password),
        },
    )


# ---------------------------------------------------------------------------
# E-5. 서브도메인 구조 이상
# ---------------------------------------------------------------------------
def check_subdomain_anomaly(result: ParseResult) -> AnalysisRecord:
    """
    서브도메인 구조가 비정상인지 판정한다.

        https://naver.com.account-verify.security-center.evil-host.com/login
                ^^^^^^^^^ 서브도메인에 끼워 넣은 TLD          ^^^^^^^^^^^^^ 실제 등록 도메인

    사람은 왼쪽부터 읽다가 naver.com을 보고 네이버로 착각한다. 실제 등록
    도메인은 맨 오른쪽 evil-host.com이다.

    [깊이 임계가 3이 아니라 4인 이유]
    s3.dualstack.us-east-1.amazonaws.com 처럼 정상 인프라가 깊이 3을 쓰는
    경우가 흔하다. 3을 기준으로 삼으면 AWS·CDN 계열이 대량 오탐된다. 깊이만으로는
    판별력이 약하므로 임계를 한 단계 올리고, 깊이 자체는 탐지 여부와 무관하게
    value에 남겨 종합 단계가 참고할 수 있게 한다.

    [TLD 목록으로 PSL을 쓰는 이유]
    AWS Route53의 "등록 가능 TLD 목록"은 쓰지 않는다. 그것은 "AWS에서 살 수
    있는 TLD"이지 "정상 TLD"가 아니다. 0단계가 이미 들고 있는 PSL 스냅샷을
    그대로 써야 "우리 파서가 보는 TLD"와 어긋나지 않는다.
    """
    name = GROUP_E_SUBDOMAIN_ANOMALY
    extracted = result.extracted

    if extracted is None or not extracted.subdomain:
        return not_applicable(name)

    subdomain = extracted.subdomain.lower()
    labels = [label for label in subdomain.split(".") if label]
    depth = len(labels)

    # 서브도메인 라벨 중 PSL에 등재된 TLD가 있는지 본다.
    # www는 흔한 정상 라벨이라 제외하지 않으면 대부분의 도메인이 걸린다 —
    # 다만 www는 PSL에 없으므로 자연히 걸러진다.
    spoofed_tlds = [label for label in labels if label in _PSL_SUFFIXES]

    observation = {
        "subdomain": subdomain,
        "subdomain_depth": depth,
        "tld_spoofing_detected": bool(spoofed_tlds),
    }

    detection_type = []
    if spoofed_tlds:
        detection_type.append("TLD_IN_SUBDOMAIN")
    if depth >= _SUBDOMAIN_DEPTH_THRESHOLD:
        detection_type.append("DEEP_SUBDOMAIN")

    if detection_type:
        value = {"detection_type": detection_type, **observation}
        if spoofed_tlds:
            value["matched_tlds"] = spoofed_tlds
        return detected(name, value)

    # 미탐지여도 깊이와 검사 결과는 남긴다.
    return not_applicable(name, value=observation)


# registry가 순차 실행할 때 참조하는 목록.
# 각 함수는 ParseResult 하나만 받고 AnalysisRecord 하나를 돌려주는 동일한 형태다.
GROUP_E_DETECTORS = (
    check_dga_pattern,
    check_long_url,
    check_base64,
    check_host_spoofing,
    check_subdomain_anomaly,
)
