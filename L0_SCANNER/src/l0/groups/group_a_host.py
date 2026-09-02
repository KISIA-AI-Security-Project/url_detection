"""
그룹 A — 호스트 구조 이상 탐지

A-1 IP 호스트 / A-2 비정상·의심 eTLD / A-3 무료 발급 도메인 / A-4 비표준 포트

모든 판정은 0단계(parsing.py)가 만든 ParseResult만 입력으로 받으며,
외부 접속을 일절 하지 않는다.
"""

from __future__ import annotations

import ipaddress
import logging

from l0.common import (
    GROUP_A_FREE_ISSUED_DOMAIN,
    GROUP_A_IP_HOST,
    GROUP_A_NONSTANDARD_PORT,
    GROUP_A_SUSPICIOUS_TLD,
)
from l0.models import AnalysisRecord, detected, not_applicable
from l0.parsing import ParseResult
from l0.data.free_hosting import FREE_HOSTING_PROVIDERS, FREE_HOSTING_VERSION
from l0.data.tld_lists import (
    TLD_BLACK,
    TLD_BLACK_VERSION,
)

logger = logging.getLogger(__name__)

# A-4: 스킴별 기본 포트.
# WHATWG 파서는 스킴의 기본 포트가 명시된 경우(https://a.com:443/) port를 ''로
# 정규화해 돌려준다. 따라서 port에 값이 남아 있다는 것은 이미 "기본 포트가 아니다"라는
# 뜻이다. 스킴별로 따로 두는 이유는 http://a.com:443 처럼 스킴과 어긋난 포트를
# 명시한 경우를 놓치지 않기 위함이다(이 경우 파서가 정규화하지 않아 '443'이 남는다).
# ws/wss는 HTTP 연결에서 승격되는 웹 플랫폼의 일부라 기본 포트가 http/https와 같다.
# wss://a.com:8443은 https://a.com:8443과 동일한 신호이므로 함께 판정한다.
# ftp/ssh 등 비웹 프로토콜은 "포트가 몇 번이냐"가 아니라 "웹이 아니다"가 핵심
# 신호이므로 F-1(비표준 프로토콜)이 스킴 자체로 잡는다. 여기서는 다루지 않는다.
DEFAULT_PORT_BY_SCHEME = {
    "http": "80",
    "https": "443",
    "ws": "80",
    "wss": "443",
}


# ---------------------------------------------------------------------------
# A-1. IP 호스트
# ---------------------------------------------------------------------------
def check_ip_host(result: ParseResult) -> AnalysisRecord:
    """
    호스트가 도메인이 아니라 IP 주소인지 판정한다.

    0단계에서 WHATWG 파서가 이미 10진수(3232235521)·16진수(0xC0.0x00.0x02.0xEB)·
    8진수 표기를 전부 점 4개짜리 표준형으로 정규화한 뒤이므로, host_type만 보면
    이런 우회 표기까지 한 번에 걸러진다. 별도의 우회 방지 로직이 필요 없다.
    """
    name = GROUP_A_IP_HOST
    parsed = result.parsed
    if parsed is None:      # 파싱 실패
        return not_applicable(name)

    if parsed.host_type not in ("IPV4", "IPV6"):     # IP 아닌 일반 호스트
        return not_applicable(name)

    # WHATWG hostname 게터는 IPv6를 대괄호로 감싸 돌려준다("[2001:db8::1]").
    # URL 재조립을 위한 스펙상의 표기인데 ipaddress는 순수 주소만 받으므로 벗겨야 한다.
    # 벗기지 않으면 정상 IPv6가 전부 PARSER_MISMATCH로 찍혀 아래 경고가 상시 울리고,
    # 정작 진짜 파서 불일치가 노이즈에 묻힌다.
    host = parsed.hostname
    address = host[1:-1] if host.startswith("[") and host.endswith("]") else host

    # 방어적 이중 확인: 파서 버전 차이 등으로 host_type과 실제 값이 어긋나는지 검사.
    # 정상 흐름에서는 절대 실패하지 않아야 한다.
    try:
        ipaddress.ip_address(address)
        ip_type = "VALID_IP"
    except ValueError:
        logger.warning(
            "host_type=%s인데 ipaddress가 거부함 (hostname=%r) — 파서 불일치 의심",
            parsed.host_type,
            host,
        )
        ip_type = "PARSER_MISMATCH"

    # host는 URL 표기 그대로(IPv6면 대괄호 포함), address는 후속 단계가 조회에 쓸 순수 주소.
    return detected(name, {"host": host, "address": address, "ip_type": ip_type})


# ---------------------------------------------------------------------------
# A-2. 비정상/의심 eTLD
# ---------------------------------------------------------------------------
def check_suspicious_tld(result: ParseResult) -> AnalysisRecord:
    """
    eTLD가 피싱 빈발 목록에 있는지 판정한다.

    화이트리스트는 쓰지 않는다(data/tld_lists.py 설계 메모 참고).
    PSL에 존재하지 않는 문자열은 tldextract가 suffix를 ''로 돌려주므로 자연히 걸러진다.

    길이는 탐지 트리거가 아니다. 정상 gTLD도 길이가 다양해(.photography 11자,
    .travelersinsurance 19자) 길이만으로는 이상 여부를 가를 수 없다. 대신 탐지
    여부와 무관하게 관찰 사실로 value에 남겨, 종합 단계가 참고할 수 있게 한다.
    """
    name = GROUP_A_SUSPICIOUS_TLD
    extracted = result.extracted
    parsed = result.parsed
    list_version = {"tld_black": TLD_BLACK_VERSION}

    # IP 호스트이거나 로컬 도메인이라 suffix가 없는 경우는 검사 대상이 아니다.
    if parsed is None or extracted is None or not extracted.suffix:
        return not_applicable(name, list_version=list_version)

    suffix = extracted.suffix.lower()
    # 다단계 eTLD(co.kr, com.au 등)는 마지막 라벨로 블랙리스트를 대조한다.
    # 'foo.tk'와 'foo.co.tk'가 모두 tk 계열로 잡히도록 하기 위함이다.
    last_label = suffix.rsplit(".", 1)[-1]
    # 길이도 마지막 라벨 기준으로 잰다. 다단계 eTLD는 전체 길이가 길어지는 게
    # 정상이라(com.au) 통째로 재면 정상 도메인이 길어 보인다.
    length = len(last_label)

    if last_label in TLD_BLACK:
        return detected(
            name,
            {"suffix": suffix, "matched": last_label, "length": length},
            list_version=list_version,
        )

    # 미탐지여도 관찰한 사실은 남긴다.
    return not_applicable(
        name,
        value={"suffix": suffix, "length": length},
        list_version=list_version,
    )


# ---------------------------------------------------------------------------
# A-3. 무료 발급 도메인
# ---------------------------------------------------------------------------
def check_free_issued_domain(result: ParseResult) -> AnalysisRecord:
    """
    무료 호스팅·서버리스·DDNS·터널링 서비스가 발급한 서브도메인인지 판정한다.

    루트 도메인 자체(예: workers.dev)는 서비스 제공자의 것이므로 탐지 대상이 아니다.
    서브도메인이 붙어 있을 때(예: kakao-login.workers.dev)만 제3자가 발급받은
    영역이므로 탐지한다.
    """
    name = GROUP_A_FREE_ISSUED_DOMAIN
    extracted = result.extracted
    list_version = {"free_hosting": FREE_HOSTING_VERSION}

    # registered_domain 비는 경우
    if extracted is None or not extracted.registered_domain:
        return not_applicable(name, list_version=list_version)

    registered = extracted.registered_domain.lower()
    # 목록에 없는 평범한 도메인 — 실제 트래픽의 대부분이 여기서 빠진다.
    category = FREE_HOSTING_PROVIDERS.get(registered)
    if category is None:
        return not_applicable(name, list_version=list_version)

    if not extracted.subdomain:
        # 서비스 제공자의 루트 도메인 자체 — 정상
        return not_applicable(name, list_version=list_version)

    # 제공자만이 아니라 실제 발급된 서브도메인까지 남긴다.
    # 어떤 이름으로 발급받았는지가 캠페인 식별의 핵심 단서다.
    # category는 위협 성격을 가른다 — 수단형(SERVERLESS/HOSTING)은 피싱 페이지
    # 배포, 상품형(DDNS/TUNNEL)은 C2 채널과 데이터 반출에 주로 쓰인다.
    return detected(
        name,
        {
            "provider": registered,
            "subdomain": extracted.subdomain.lower(),
            "category": category,
        },
        list_version=list_version,
    )


# ---------------------------------------------------------------------------
# A-4. 비표준 포트
# ---------------------------------------------------------------------------
def check_nonstandard_port(result: ParseResult) -> AnalysisRecord:
    """
    스킴의 기본 포트가 아닌 포트를 명시했는지 판정한다.

    포트가 비어 있으면(파서가 기본 포트를 정규화해 지웠거나 애초에 생략) 정상이다.
    값이 남아 있다면 스킴의 기본 포트와 다른 것이므로 탐지 대상이다.
    """
    name = GROUP_A_NONSTANDARD_PORT
    parsed = result.parsed
    if parsed is None or not parsed.port:
        return not_applicable(name)

    scheme = parsed.protocol.rstrip(":").lower()
    default_port = DEFAULT_PORT_BY_SCHEME.get(scheme)

    # 표에 없는 스킴은 웹이 아니므로 판정 대상이 아니다.
    # ada는 special scheme의 기본 포트만 정규화해 지운다. 따라서 "port가 남아 있다 =
    # 기본 포트가 아니다"라는 이 함수의 전제는 웹 스킴에서만 성립한다. 게이트가 없으면
    # ssh://a.com:22(표준 포트)까지 비표준 포트로 오탐한다.
    if default_port is None:
        return not_applicable(name)

    return detected(
        name,
        {"port": parsed.port, "scheme": scheme, "expected_port": default_port},
    )


# registry가 순차 실행할 때 참조하는 목록.
# 각 함수는 ParseResult 하나만 받고 AnalysisRecord 하나를 돌려주는 동일한 형태다.
GROUP_A_DETECTORS = (
    check_ip_host,
    check_suspicious_tld,
    check_free_issued_domain,
    check_nonstandard_port,
)
