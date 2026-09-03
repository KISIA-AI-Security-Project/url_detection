"""
그룹 A-2(비정상/의심 eTLD) 판정에 쓰는 TLD 목록.

[설계 메모] 초안에 있던 TLD_WHITE(AWS Route53 등록 가능 TLD 목록)는 채택하지 않았다.
그 목록은 "AWS에서 도메인을 구매할 수 있는 TLD"이지 "정상적인 TLD"가 아니다.
- .xyz, .top 같은 피싱 빈발 TLD도 AWS가 판매하므로 화이트리스트에 포함되어 버린다
- 반대로 AWS가 취급하지 않는 정상 국가 TLD는 누락된다
따라서 화이트리스트 없이 (1) 블랙리스트 (2) 길이 이상 두 축으로만 판정한다.
PSL에 아예 없는 문자열은 tldextract가 suffix를 빈 문자열로 돌려주므로 그것으로 걸러진다.

[갱신 주기] 분기 1회. 원 출처가 분기별로 데이터를 갱신하므로 그에 맞춘다.
갱신 시 LIST_VERSION의 날짜를 반드시 함께 수정할 것.
"""

# 목록 버전 — analysis_record의 list_version에 실려 저장된다.
# 어떤 시점의 목록으로 판정했는지 남겨야 나중에 결과를 재현·감사할 수 있다.
# Interisle에서 운영하는 CIC에서 제공하는 데이터
# 2026년 2~4월 피싱 데이터를 근거로 만든 블랙리스트
# 형식: "<목록명>-<기간>" (free_hosting.py와 동일 규약)
TLD_BLACK_VERSION = "tld_black-2026Q2"

# ---------------------------------------------------------------------------
# 1차 출처: Cybercrime Information Center (Interisle Consulting Group)
#   "Phishing Activity in Top-level Domains, February 1 - April 30, 2026"
#   https://www.cybercrimeinfocenter.org/phishing-activity-in-tlds-february-april-2026
#
#   채택 기준: "Phishing Domain Score" 상위 목록.
#   이 점수는 (해당 TLD의 피싱 도메인 수 / 해당 TLD의 전체 등록 도메인 수) * 10,000 으로,
#   TLD 규모 차이를 정규화한 지표다. 단순 피싱 건수로 줄을 세우면 .com이 1위가 되어
#   블랙리스트로 쓸 수 없으므로, 반드시 이 정규화된 점수를 기준으로 삼는다.
#   임계값: score >= 100 (= 등록 도메인 1만 개당 피싱 도메인 100개 이상)
#
# 교차 검증: alphaMountain "10 Riskiest TLDs" (2026-05-15 기준 데이터셋),
#   Spamhaus 최다 악용 TLD, Netcraft 사이버범죄 비율 상위 TLD와 대조하여
#   복수 출처에서 공통으로 지목된 항목 위주로 구성.
# ---------------------------------------------------------------------------
TLD_BLACK = {
    # --- Interisle 2026 Q1 피싱 점수 상위 20 (score >= 140) ---
    "garden",  # 1,566.5 — 압도적 1위
    "mom",     # 726.4
    "xin",     # 652.2
    "rest",    # 417.3
    "cfd",     # 406.1
    "help",    # 334.7
    "ink",     # 329.3
    "icu",     # 305.0
    "cam",     # 304.0
    "life",    # 231.8
    "lat",     # 206.7
    "cyou",    # 203.2
    "top",     # 197.6 — 절대 건수로도 2위(124,452건)
    "fit",     # 196.1
    "fyi",     # 187.4
    "homes",   # 173.1
    "pics",    # 164.9
    "one",     # 144.0
    "click",   # 143.6
    "bond",    # 143.0
    # --- score 100~140 구간 ---
    "sbs",     # 125.6
    "pro",     # 123.9
    "vip",     # 109.1
    # --- score는 100 미만이나 절대 건수가 매우 크고, alphaMountain 기준
    #     "risky fraction"이 30%를 넘어 복수 출처가 공통 지목한 항목 ---
    "shop",    # score 53.0 / 피싱 20,888건 / alphaMountain risky 32.6%
    "cc",      # score 73.8 / 피싱 17,936건
    "xyz",     # score 26.1 / 피싱 20,738건 / alphaMountain risky 54.9%
    # --- 구 Freenom 계열 (제외) ---
    #     무료 등록 + 신원 확인 부재로 오랫동안 피싱 인프라의 대표 격이었으나,
    #     2023년 Meta 소송 이후 Freenom이 도메인 사업에서 철수하며 약 1,260만 개가
    #     삭제되었고, 2026년 재개된 .tk/.cf/.gq는 유료(연 €8.22)로 전환되었다.
    #     .ga는 Afnic, .ml은 말리 정부로 이관되어 운영자 자체가 바뀌었다.
    #     즉 "무료 + 익명"이라는 남용의 근본 조건이 사라졌다.
    #     이 5개는 score 기준이 아니라 역사적 근거로 채택된 항목이다.
    #     최신 분기 CIC 보고서 순위표에 이 5개가 나타나지 않으므로 제외한다.
    # "tk",
    # "ml",
    # "ga",
    # "cf",
    # "gq",
}