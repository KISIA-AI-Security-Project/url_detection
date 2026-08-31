"""
그룹 B — 텍스트 트릭 탐지

B-1 콤보스쿼팅 / B-2 타이포스쿼팅 / B-3 퓨니코드 위장

세 판정 모두 호스트 문자열만 본다. 경로·쿼리의 브랜드명은 다루지 않는다
(스쿼팅은 정의상 도메인 등록 행위이며, 경로는 등록 없이 누구나 쓸 수 있어
증거 가치가 다르다).
"""

from __future__ import annotations

import logging
import unicodedata

from l0.common import (
    GROUP_B_COMBOSQUATTING,
    GROUP_B_PUNYCODE_SPOOF,
    GROUP_B_TYPOSQUATTING,
)
from l0.models import AnalysisRecord, detected, not_applicable
from l0.parsing import ParseResult
from l0.data.brands import BRAND_DOMAINS, BRANDS_VERSION, LEGIT_DOMAINS
from l0.data.unicode_scripts import (
    ALLOWED_SCRIPT_SETS,
    NEUTRAL_SCRIPTS,
    SCRIPT_ALIASES,
)
from l0.data.confusables import (
    ASCII_CONFUSABLE_MAP,
    ASCII_CONFUSABLE_SEQUENCES,
    ASCII_CONFUSABLES_VERSION,
    CONFUSABLE_MAP,
    CONFUSABLES_VERSION,
    NM_FOLD_MAP,
    NM_FOLD_SEQUENCES,
)

logger = logging.getLogger(__name__)

# B-2 공통: 이보다 짧은 브랜드는 판정 대상에서 제외한다.
# 이웃 밀도(영어 단어 사전 기준) 길이 4의 거리1 값이 허용 기준 11을 넘고,
# 코퍼스에서도 4자 브랜드 toss가 잡은 7건 중 4건이 무관한 문자열이었다
# (descontos50, photos5612 등). 두 근거가 같은 결론을 가리킨다.
_MIN_BRAND_LENGTH = 5

# B-2 시각적 유사: n<->m 접기를 허용할 최소 브랜드 길이.
# 5자 naver가 영어 형태소 'maver-'와 충돌해 오귀속 10건을 만들었다
# (superprimavera, appsmavericks, maverickinfotec 등).
_NM_FOLD_MIN_BRAND_LENGTH = 6

# B-2 오타 유도: 최소 도메인 길이.
# 시각적 유사 경로에는 적용하지 않는다 — 브랜드가 5자 이상이므로 포함 관계가
# 성립하는 도메인도 자동으로 5자 이상이라, 하한을 둬도 아무 일도 하지 않는다.
_MIN_DOMAIN_LENGTH = 5

# B-2 오타 유도: 이 길이 이하 브랜드는 편집거리 1까지만, 초과하면 2까지 허용한다.
# 이웃 밀도 기준 — 길이 7은 거리1에서 허용 기준 이내, 거리2에서 초과다.
_SHORT_BRAND_LENGTH = 7
_DISTANCE_SHORT_BRAND = 1
_DISTANCE_LONG_BRAND = 2


# ---------------------------------------------------------------------------
# B-1. 콤보스쿼팅
# ---------------------------------------------------------------------------
def check_combosquatting(result: ParseResult) -> AnalysisRecord:
    """
    브랜드명이 호스트에 철자 그대로 들어 있으나 정식 도메인이 아닌지 판정한다.

    kakao-login.com, kakao.evil.com 처럼 브랜드명을 다른 토큰과 결합하거나
    서브도메인에 끼워 넣는 수법을 잡는다. 철자를 비트는 타이포스쿼팅(B-2)과 달리
    브랜드명 자체는 정확히 들어 있다.

    도메인 라벨이 브랜드명과 정확히 일치하는 경우(kakao.xyz)는 여기서 판정하지
    않는다. 같은 형태인 amazon.fr(정상 프랑스 아마존)과 문자열만으로 구분할 수
    없고, 글로벌 브랜드의 국가별 ccTLD를 전부 담는 것도 불가능하기 때문이다.
    이 경우는 A-2(의심 TLD)가 TLD 쪽에서 판단한다.
    """
    name = GROUP_B_COMBOSQUATTING
    extracted = result.extracted
    list_version = {"brands": BRANDS_VERSION}

    if extracted is None or not extracted.domain:
        return not_applicable(name, list_version=list_version)

    registered = extracted.registered_domain.lower()
    # LEGIT_DOMAINS는 브랜드가 직접 등록한 도메인 집합이다(kakao.com 등).
    # 여기 해당하면 호스트에 브랜드명이 있어도 사칭이 아니라 본인 소유다.
    # login.kakao.com도 registered_domain이 kakao.com이라 여기서 걸러진다.
    if registered in LEGIT_DOMAINS:
        return not_applicable(name, list_version=list_version)

    domain = extracted.domain.lower()
    subdomain = extracted.subdomain.lower()
    # eTLD를 뺀 부분에서만 찾는다. suffix까지 넣으면 .shop 같은 TLD가 잡음이 된다.
    host_head = f"{subdomain}.{domain}" if subdomain else domain

    for brand in BRAND_DOMAINS:
        if brand not in host_head:
            continue

        if domain == brand:
            # 브랜드명 그대로에 다른 TLD — A-2의 영역이므로 넘긴다.
            # 다른 브랜드가 서브도메인에 또 들어 있을 수 있으므로 순회는 계속한다.
            continue

        match_type = "COMBINED_DOMAIN" if brand in domain else "SUBDOMAIN"
        return detected(
            name,
            {
                "brand": brand,
                "match_type": match_type,
                "registered_domain": registered,
            },
            list_version=list_version,
        )

    return not_applicable(name, list_version=list_version)


# ---------------------------------------------------------------------------
# B-2. 타이포스쿼팅
# ---------------------------------------------------------------------------
def check_typosquatting(result: ParseResult) -> AnalysisRecord:
    """
    도메인 라벨이 브랜드명과 시각적으로 같거나 오타 수준으로 유사한지 판정한다.

    브랜드명이 철자 그대로 들어 있는 경우는 B-1의 영역이므로 건너뛴다.

    두 경로를 순서대로 본다.
    1) 시각적 유사 — 혼동 문자를 접은 골격이 일치하는가 (g00gle -> google).
       사람이 0과 o를 실수로 바꿔 치지는 않는다. 골격이 맞는다는 것은 사실상
       의도적 등록이라는 뜻이라 편집거리보다 강한 신호이고, 그래서 먼저 본다.
       순서를 뒤집으면 놓친다 — g00gle은 google과 편집거리 2인데 6자 브랜드의
       임계값은 1이라 편집거리 경로에서 걸러진다.
    2) 오타 유도 — 편집거리가 브랜드 길이별 임계 이내인가 (navor -> naver).
    """
    name = GROUP_B_TYPOSQUATTING
    extracted = result.extracted
    list_version = {
        "brands": BRANDS_VERSION,
        "ascii_confusables": ASCII_CONFUSABLES_VERSION,
    }

    if extracted is None or not extracted.domain:
        return not_applicable(name, list_version=list_version)

    domain = extracted.domain.lower()

    # 브랜드명이 온전히 들어 있으면 오타가 아니라 결합이다 (B-1 담당).
    # 정식 도메인(naver.com -> naver)도 이 조건에서 함께 걸러진다.
    candidates = {
        brand
        for brand in _TARGET_BRANDS
        if brand not in domain and domain not in brand
    }

    # --- 1) 시각적 유사 ---------------------------------------------------
    # 도메인 골격은 두 벌 만든다. 브랜드마다 n<->m 접기 여부가 달라 한 벌로는
    # 짝을 맞출 수 없다. 설정이 두 종뿐이라 두 번만 계산하면 된다.
    domain_skeletons = {
        False: _ascii_skeleton(domain, fold_nm=False),
        True: _ascii_skeleton(domain, fold_nm=True),
    }

    for brand, brand_skeleton, fold_nm in _VISUAL_TARGETS:
        if brand not in candidates:
            continue
        if brand_skeleton in domain_skeletons[fold_nm]:
            return detected(
                name,
                {
                    "brand": brand,
                    "domain": domain,
                    "skeleton": domain_skeletons[fold_nm],
                    "detection_type": "VISUAL_SIMILAR",
                },
                list_version=list_version,
            )

    # --- 2) 오타 유도 -----------------------------------------------------
    if len(domain) < _MIN_DOMAIN_LENGTH:
        return not_applicable(name, list_version=list_version)

    best_brand = None
    best_distance = None

    for brand, threshold in _EDIT_TARGETS:
        if brand not in candidates:
            continue
        distance = _levenshtein_within(domain, brand, threshold)
        if distance is None:
            continue
        if best_distance is None or distance < best_distance:
            best_brand, best_distance = brand, distance
            # candidates가 완전 일치를 이미 걸렀으므로 거리 0은 나올 수 없다.
            # 1이 가능한 최솟값이라 더 볼 이유가 없다. 뒤에 또 거리 1이 나와도
            # "동률이면 먼저 순회한 브랜드"라는 규칙상 결과가 같다.
            if distance == 1:
                break

    if best_brand is None:
        return not_applicable(name, list_version=list_version)

    return detected(
        name,
        {
            "brand": best_brand,
            "domain": domain,
            "distance": best_distance,
            "detection_type": "EDIT_DISTANCE",
        },
        list_version=list_version,
    )


def _ascii_skeleton(text: str, *, fold_nm: bool) -> str:
    """
    ASCII 혼동 문자를 접어 시각적 골격을 만든다.

    브랜드와 도메인 양쪽에 같은 함수를 쓴다. 한쪽만 접으면 브랜드 instagram과
    도메인 1nstagram이 서로 다른 자리에 남아 영원히 만나지 못한다.

    fold_nm은 n<->m 접기 적용 여부다. 브랜드 길이에 따라 갈리므로 호출자가 정한다.

    여러 글자가 한 글자로 보이는 경우(rn -> n)를 먼저 처리한 뒤 문자 단위로
    치환한다. 순서를 바꾸면 r과 n이 각각 접혀 한 글자로 합쳐지지 않는다.
    """
    sequences, mapping = _SKELETON_RULES[fold_nm]
    for sequence, replacement in sequences:
        text = text.replace(sequence, replacement)
    return "".join(mapping.get(c, c) for c in text)


def _levenshtein_within(a: str, b: str, max_distance: int) -> int | None:
    """
    편집거리를 계산하되 max_distance를 넘으면 즉시 포기하고 None을 돌려준다.

    브랜드 수만큼 반복 호출되므로 전체 거리를 끝까지 계산할 이유가 없다.
    탈락이 확정되면 최종값이 3인지 6인지는 알 필요가 없다.
    """
    # 길이차가 임계보다 크면 그 차이만큼은 반드시 고쳐야 하므로 계산할 필요가 없다.
    if abs(len(a) - len(b)) > max_distance:
        return None

    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            current.append(
                min(
                    previous[j] + 1,               # 삭제
                    current[j - 1] + 1,            # 삽입
                    previous[j - 1] + (ca != cb),  # 치환
                )
            )
        # 지금까지의 최소 편집 횟수가 이미 임계를 넘었다면, 편집 횟수는 앞으로
        # 줄어들 수 없으므로 최종 거리도 반드시 임계를 넘는다. 여기서 포기한다.
        if min(current) > max_distance:
            return None
        previous = current

    distance = previous[-1]
    return distance if distance <= max_distance else None


# fold_nm 두 경우의 규칙을 미리 합쳐둔다. 호출마다 dict를 만들지 않기 위함.
_SKELETON_RULES: dict[bool, tuple[tuple[tuple[str, str], ...], dict[str, str]]] = {
    False: (ASCII_CONFUSABLE_SEQUENCES, ASCII_CONFUSABLE_MAP),
    True: (
        ASCII_CONFUSABLE_SEQUENCES + NM_FOLD_SEQUENCES,
        {**ASCII_CONFUSABLE_MAP, **NM_FOLD_MAP},
    ),
}

# B-2 판정 대상 브랜드. 두 경로 모두 _MIN_BRAND_LENGTH 이상만 본다.
_TARGET_BRANDS = tuple(b for b in BRAND_DOMAINS if len(b) >= _MIN_BRAND_LENGTH)

# 브랜드 골격은 모듈 로드 시 1회만 만든다. 브랜드는 길이가 고정이므로
# n<->m 접기 적용 여부도 브랜드마다 하나로 확정된다.
# 세 번째 원소 fold_nm은 어느 도메인 골격과 짝지을지를 정한다.
_VISUAL_TARGETS: tuple[tuple[str, str, bool], ...] = tuple(
    (
        brand,
        _ascii_skeleton(brand, fold_nm=len(brand) >= _NM_FOLD_MIN_BRAND_LENGTH),
        len(brand) >= _NM_FOLD_MIN_BRAND_LENGTH,
    )
    for brand in _TARGET_BRANDS
)

# 편집거리 임계값도 브랜드 길이로 결정되므로 미리 계산해둔다.
_EDIT_TARGETS: tuple[tuple[str, int], ...] = tuple(
    (
        brand,
        _DISTANCE_SHORT_BRAND
        if len(brand) <= _SHORT_BRAND_LENGTH
        else _DISTANCE_LONG_BRAND,
    )
    for brand in _TARGET_BRANDS
)



# ---------------------------------------------------------------------------
# B-3. 퓨니코드 위장
# ---------------------------------------------------------------------------
def check_punycode_spoof(result: ParseResult) -> AnalysisRecord:
    """
    IDN 라벨을 디코딩해 두 가지를 본다.

    (1) 혼합 스크립트 — 한 라벨 안에 호환되지 않는 스크립트가 섞였는가.
        ada가 모든 IDN을 punycode로 정규화하므로 'xn--' 접두어만 보면 IDN 여부는
        바로 알 수 있다. 문제는 그다음인데, 정상 한글·일본어 도메인도 IDN이므로
        'xn--이면 위장'으로 보면 안 된다. UTS #39 Highly Restrictive 기준으로
        라틴+키릴처럼 정상적으로 섞일 수 없는 조합만 걸러낸다.

    (2) 혼동 문자 — 라틴으로 접었을 때 브랜드명이 되는가.
        (1)은 전체 스크립트 위장을 놓친다. 'apple'을 한 글자도 빠짐없이 키릴로
        쓴 xn--80ak6aa92e.com은 단일 스크립트라 혼합 검사를 통과하기 때문이다.
        그래서 skeleton으로 접어 브랜드 목록과 대조하는 2차 검사를 둔다.

    두 검사의 순서는 바꾸지 않는다. 혼합 스크립트는 브랜드 목록과 무관하게
    성립하는 구조적 이상이라 더 넓고 강한 신호다.

    [라벨 단위로 보는 이유]
    호스트 전체를 한 번에 디코딩해 스크립트를 뽑으면 TLD가 항상 라틴이라
    모든 IDN이 무조건 혼합으로 잡힌다. 한국.kr은 HANGUL+LATIN, 日本語.jp는
    CJK+LATIN이 되어 정상 도메인이 전부 오탐된다. 스크립트 혼합은 한 라벨
    안에서만 의미가 있다.
    """
    name = GROUP_B_PUNYCODE_SPOOF
    parsed = result.parsed
    list_version = {
        "unicodedata": unicodedata.unidata_version,
        "brands": BRANDS_VERSION,
        "confusables": CONFUSABLES_VERSION,
    }

    if parsed is None or not parsed.hostname:
        return not_applicable(name, list_version=list_version)

    host = parsed.hostname
    if host.startswith("["):
        return not_applicable(name, list_version=list_version)  # IPv6 리터럴

    for label in host.split("."):
        if not label.startswith("xn--"):
            continue

        try:
            decoded = _punycode_decode(label)
        except (UnicodeError, ValueError):
            # ada가 통과시킨 라벨이 디코딩되지 않는 것은 그 자체로 비정상이다.
            logger.warning("punycode 디코딩 실패 (label=%r)", label)
            return detected(
                name,
                {"label": label, "detection_type": "INVALID_PUNYCODE"},
                list_version=list_version,
            )

        scripts = _scripts_in(decoded)
        if len(scripts) > 1 and not _is_allowed_combination(scripts):
            return detected(
                name,
                {
                    "label": label,
                    "decoded": decoded,
                    "scripts": sorted(scripts),
                    "detection_type": "MIXED_SCRIPT",
                },
                list_version=list_version,
            )

        skeleton = _skeleton(decoded)
        # skeleton이 원문과 같으면 접힌 문자가 없다는 뜻 — 위장 시도 자체가 없다.
        # 한글·일본어 도메인은 대응하는 라틴 문자가 없어 항상 여기서 걸러진다.
        if skeleton == decoded:
            continue

        for brand in BRAND_DOMAINS:
            if brand in skeleton:
                return detected(
                    name,
                    {
                        "label": label,
                        "decoded": decoded,
                        "skeleton": skeleton,
                        "brand": brand,
                        "detection_type": "CONFUSABLE_BRAND",
                    },
                    list_version=list_version,
                )

    return not_applicable(name, list_version=list_version)


def _skeleton(text: str) -> str:
    """
    시각적으로 동등한 라틴 표기로 접는다.

    두 단계다.
    1) NFKD 정규화 후 결합 문자를 버린다 — googlé -> google, ａpple -> apple.
       발음부호와 전각 문자는 유니코드가 이미 대응 관계를 정의하고 있으므로
       별도 표를 만들 이유가 없다.
    2) NFKD가 접어주지 않는 타 스크립트 동형 문자를 표로 치환한다 -
       키릴 а, 그리스 ο 등은 라틴 문자와 '다른 글자'라 정규화 대상이 아니다.
    """
    decomposed = unicodedata.normalize("NFKD", text)
    stripped = "".join(c for c in decomposed if not unicodedata.combining(c))
    return "".join(CONFUSABLE_MAP.get(c, c) for c in stripped).lower()


def _punycode_decode(label: str) -> str:
    """
    'xn--' 접두어를 뗀 뒤 punycode로 디코딩한다.

    idna 코덱이 아니라 순수 punycode를 쓰는 이유는, IDNA 검증은 이미 ada가
    끝냈고 여기서 다시 검증하면 표준 판본 차이(IDNA2003/2008)로 정상 도메인이
    거부될 수 있기 때문이다.
    """
    return label[4:].encode("ascii").decode("punycode")


def _scripts_in(text: str) -> set[str]:
    """문자열에 쓰인 스크립트 집합. 숫자·기호 등 중립 문자는 제외한다."""
    scripts = set()
    for ch in text:
        if not ch.isalpha():
            continue
        script = unicodedata.name(ch, "").split(" ")[0]
        script = SCRIPT_ALIASES.get(script, script)
        if script and script not in NEUTRAL_SCRIPTS:
            scripts.add(script)
    return scripts


def _is_allowed_combination(scripts: set[str]) -> bool:
    """UTS #39 Highly Restrictive가 허용하는 조합인지 검사한다."""
    return any(scripts <= allowed for allowed in ALLOWED_SCRIPT_SETS)


# registry가 순차 실행할 때 참조하는 목록.
# 각 함수는 ParseResult 하나만 받고 AnalysisRecord 하나를 돌려주는 동일한 형태다.
GROUP_B_DETECTORS = (
    check_combosquatting,
    check_typosquatting,
    check_punycode_spoof,
)