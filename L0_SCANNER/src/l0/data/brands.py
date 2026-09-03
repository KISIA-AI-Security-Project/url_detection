"""
그룹 B-1(콤보스쿼팅)·B-2(타이포스쿼팅) 판정에 쓰는 브랜드 목록.

[구조] 브랜드 키워드 -> 그 브랜드의 정식 등록 도메인 집합.
하나의 표가 두 판정을 모두 받친다. 키워드는 "호스트에서 찾을 문자열"이고,
값은 "찾았을 때 정상으로 보아 넘길 도메인"이다. 목록을 둘로 나누면 갱신이
어긋나므로(C-1/C-2에서 겪은 문제) 단일 테이블로 유지한다.

[키워드 선정 기준]
- 소문자 ASCII, 4자 이상. 3자 이하(kt, cj, ssg, nh, ibk, dhl, ups)는 무작위
  문자열에 우연히 포함될 확률이 높아 제외했다.
- 일반 영어 단어와 겹치는 것은 원칙적으로 제외(steam, chase, one, rest).
  다만 'toss'는 국내 피싱 빈도가 압도적으로 높아 오탐을 감수하고 포함한다.

[정식 도메인 집합의 한계]
글로벌 브랜드는 국가별 ccTLD를 다 담을 수 없다(google.de, amazon.fr ...).
그래서 B-1은 "브랜드명 그대로에 다른 TLD"인 경우를 아예 판정하지 않는다.
문자열만으로는 정상 ccTLD와 사칭(kakao.xyz)을 구분할 수 없기 때문이다.
이 형태는 A-2(의심 TLD)가 TLD 쪽에서 잡는다.

[갱신 주기] 반기 1회. 국내 서비스 개편·신규 사칭 대상 등장 시 수시 반영.
"""

# 목록 버전 — analysis_record의 list_version에 실려 저장된다.
BRANDS_VERSION = "brands-2026-08"

BRAND_DOMAINS: dict[str, frozenset[str]] = {
    # ------------------------------------------------------------------
    # 국내 — 포털 / 커머스 / 플랫폼
    # ------------------------------------------------------------------
    "kakao": frozenset({
        "kakao.com", "kakaocorp.com", "kakaobank.com", "kakaopay.com", "daum.net",
    }),
    "naver": frozenset({"naver.com", "navercorp.com", "naver.me", "pay.naver.com"}),
    "coupang": frozenset({"coupang.com", "coupangpay.com"}),
    "baemin": frozenset({"baemin.com", "woowahan.com"}),
    "daangn": frozenset({"daangn.com"}),
    "musinsa": frozenset({"musinsa.com"}),
    "gmarket": frozenset({"gmarket.co.kr"}),
    "interpark": frozenset({"interpark.com"}),
    "yes24": frozenset({"yes24.com"}),
    "nexon": frozenset({"nexon.com"}),
    "netmarble": frozenset({"netmarble.com"}),

    # ------------------------------------------------------------------
    # 국내 — 금융
    #   보이스피싱·스미싱의 최대 사칭 대상군이다.
    # ------------------------------------------------------------------
    "toss": frozenset({"toss.im", "tossbank.com", "tossinvest.com"}),
    "kbstar": frozenset({"kbstar.com", "kbfg.com"}),
    "shinhan": frozenset({"shinhan.com", "shinhancard.com", "shinhansec.com"}),
    "wooribank": frozenset({"wooribank.com", "woorifg.com"}),
    "hanabank": frozenset({"hanabank.com", "hanafn.com"}),
    "nonghyup": frozenset({"nonghyup.com"}),
    "samsung": frozenset({
        "samsung.com", "samsungcard.com", "samsungfire.com", "samsunglife.com",
    }),
    "hyundai": frozenset({"hyundai.com", "hyundaicard.com", "hyundaicapital.com"}),
    "lotte": frozenset({"lotte.com", "lottecard.co.kr", "lotteon.com"}),
    "upbit": frozenset({"upbit.com"}),
    "bithumb": frozenset({"bithumb.com"}),

    # ------------------------------------------------------------------
    # 국내 — 공공 / 물류
    #   "택배 배송 조회", "관세 미납" 유형의 스미싱에서 반복 사용된다.
    # ------------------------------------------------------------------
    "hometax": frozenset({"hometax.go.kr"}),
    "epost": frozenset({"epost.go.kr"}),
    "korail": frozenset({"korail.com", "letskorail.com"}),
    "cjlogistics": frozenset({"cjlogistics.com"}),

    # ------------------------------------------------------------------
    # 글로벌 — 계정 탈취 표적
    # ------------------------------------------------------------------
    "paypal": frozenset({"paypal.com", "paypal.me"}),
    "microsoft": frozenset({
        "microsoft.com", "microsoftonline.com", "live.com", "office.com",
    }),
    "outlook": frozenset({"outlook.com"}),
    "google": frozenset({
        "google.com", "google.co.kr", "googleapis.com", "gmail.com", "youtube.com",
    }),
    "apple": frozenset({"apple.com", "icloud.com"}),
    "amazon": frozenset({"amazon.com", "amazon.co.kr", "amazonaws.com"}),
    "facebook": frozenset({"facebook.com", "fb.com"}),
    "instagram": frozenset({"instagram.com"}),
    "netflix": frozenset({"netflix.com"}),
    "linkedin": frozenset({"linkedin.com"}),
    "dropbox": frozenset({"dropbox.com"}),
    "adobe": frozenset({"adobe.com"}),
    "whatsapp": frozenset({"whatsapp.com"}),
    "telegram": frozenset({"telegram.org"}),
    "binance": frozenset({"binance.com"}),
    "coinbase": frozenset({"coinbase.com"}),
    "fedex": frozenset({"fedex.com"}),
}

# B-1/B-2가 "정식 도메인이면 검사 종료"에 쓰는 역인덱스.
# BRAND_DOMAINS에서 value만 모은 것.
# 매 호출마다 만들지 않도록 모듈 로드 시 1회만 계산한다.
LEGIT_DOMAINS: frozenset[str] = frozenset(
    d for domains in BRAND_DOMAINS.values() for d in domains
)
