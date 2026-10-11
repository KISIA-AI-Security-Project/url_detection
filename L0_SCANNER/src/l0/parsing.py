"""
파서: ada_url (Node.js가 사용하는 Ada 파서의 Python 바인딩, WHATWG 스펙 구현체)
쿼리 파싱: ada_url.parse_search_params (URLSearchParams 스펙 기준)
도메인 분해: tldextract (Public Suffix List 기반)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import tldextract
from ada_url import parse_search_params, parse_url

logger = logging.getLogger(__name__)

# tldextract는 기본값으로 Public Suffix List를 매번 원격에서 받아오려 시도한다.
# Lambda 환경은 아웃바운드 네트워크가 제한적이거나 없을 수 있고, 매 실행마다 외부
# 요청을 보내는 것 자체가 0단계("접속하지 않는다")의 취지에도 맞지 않으므로,
# 패키지에 내장된 스냅샷만 쓰도록 고정한다 (suffix_list_urls=() → 원격 fetch 비활성화).
# include_psl_private_domains는 기본값 False이지만 반드시 명시한다.
# True로 켜면 PSL PRIVATE DOMAINS 항목(workers.dev, github.io 등)이 suffix로 승격되어
# top_domain_under_public_suffix가 'kakao-login.workers.dev'처럼 풀 호스트가 된다.
# 그러면 A-3의 FREE_HOSTING_PROVIDERS 대조가 영원히 실패하고, 예외도 로그도 없이
# 그룹 A-3 전체가 조용히 무력화된다. A-3 목록의 출처가 PSL PRIVATE DOMAINS 섹션이라
# "그럼 이 옵션을 켜야 하지 않나" 하고 손대기 쉬운 자리이므로 경고를 남긴다.
_tldextract = tldextract.TLDExtract(
    suffix_list_urls=(),
    include_psl_private_domains=False,  # A-3이 이 값에 의존 — 바꾸지 말 것
)


class ParseStatus(str, Enum):
    """0단계 파싱 결과 상태."""

    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    EMPTY_INPUT = "EMPTY_INPUT"


@dataclass
class ParsedFields:
    """ada_url.parse_url()의 반환값 중 L0가 실제로 쓰는 필드만 추린 것."""

    href: str
    protocol: str  # 끝에 ':' 포함 (예: "https:")
    username: str
    password: str
    hostname: str
    port: str
    pathname: str
    search: str  # 앞에 '?' 포함 (예: "?q=1"), 없으면 ""
    hash: str
    host_type: str  # "IPV4" | "IPV6" | "DEFAULT"


@dataclass
class ExtractedDomain:
    """tldextract.extract(hostname)의 반환값."""

    subdomain: str
    domain: str
    suffix: str
    registered_domain: str


@dataclass
class ParseResult:
    """0단계 저장 결과 (Raw Evidence)."""

    stage: str
    raw_url: str
    parse_status: ParseStatus
    parsed: ParsedFields | None = None
    # Internal input for record checks; raw keeps the original query in parsed.search.
    query: dict[str, list[str]] = field(default_factory=dict)
    query_status: str = "absent"
    query_errors: list[dict[str, Any]] = field(default_factory=list)
    extracted: ExtractedDomain | None = None
    url_standard: str = "WHATWG"

    def to_dict(self) -> dict[str, Any]:
        """Raw Evidence 저장 형식(JSON 직렬화 가능한 dict)으로 변환."""
        return {
            "raw_evidence": {
                "stage": self.stage,
                "raw_url": self.raw_url,
                "parse_status": self.parse_status.value,
                "url_standard": self.url_standard,
                "parsed": _asdict_or_none(self.parsed),
                "query_status": self.query_status,
                "query_errors": self.query_errors,
                "extracted": _asdict_or_none(self.extracted),
            }
        }


# 데이터클래스(ParsedFields, ExtractedDomain)를 dict로 변환
def _asdict_or_none(obj: Any) -> dict[str, Any] | None:
    if obj is None:
        return None
    return {k: v for k, v in vars(obj).items()}


# WHATWG 스펙(whatwg/url#619, 2020년 개정) 기준: 호스트의 마지막 라벨이 숫자로만 구성되면
# 무조건 IPv4 파서를 태우고, 옥텟 초과 등으로 실패하면 도메인으로 되돌아가지 않고
# 호스트 자체를 무효 처리한다. ada_url은 이 케이스에서 ValueError를 던진다.
# 이 문자열은 IP로도 도메인으로도 성립하지 않으므로(브라우저도 접속 불가)
# L0 단계에서 FAILURE로 기록하고 파이프라인을 조기 종료한다.
def parse_url_stage(raw_url: str) -> ParseResult:
    """
    L0 0단계: 원본 URL 문자열을 WHATWG 기준으로 파싱한다.

    Args:
        raw_url: 원본 URL 문자열 (메일/로그 등에서 추출된 그대로)

    Returns:
        ParseResult — 성공 시 parsed/query/extracted가 채워지고,
        실패 시 parsed/extracted는 None이다.
        어느 경우든 이 결과 자체가 Raw Evidence로 저장된다.
    """
    stage = "L0_PARSE"
    # 성공·실패·빈입력 어느 경로로 끝나든 동일하게 붙는 공통 필드
    common = {
        "stage": stage,
    }

    if not raw_url or not raw_url.strip():
        logger.info("빈 URL 입력 → EMPTY_INPUT")
        return ParseResult(
            raw_url=raw_url or "",
            parse_status=ParseStatus.EMPTY_INPUT,
            **common,
        )

    try:
        r = parse_url(raw_url)
    except ValueError as e:
        logger.info("URL 파싱 실패 raw_url=%r: %s", raw_url, e)
        return ParseResult(
            raw_url=raw_url,
            parse_status=ParseStatus.FAILURE,
            **common,
        )

    parsed = ParsedFields(
        href=r["href"],
        protocol=r["protocol"],
        username=r["username"],
        password=r["password"],
        hostname=r["hostname"],
        port=r["port"],
        pathname=r["pathname"],
        search=r["search"],
        hash=r["hash"],
        host_type=r["host_type"].name,  # HostType.IPV4 -> "IPV4" (str()이 아니라 .name 필요 -
        # ada_url의 HostType은 IntEnum이라 str(v)는 "IPV4"가 아니라 정수형 "1"을 반환함)
    )

    # 항목별 엄격 파싱: 잘못된 값 하나 때문에 독립된 정상 항목까지 버리지 않는다.
    query: dict[str, list[str]] = {}
    query_errors = []
    query_status = "absent"
    if parsed.search:
        query_status = "complete"
        # Only the first '?' is the query delimiter; subsequent '?' belong to keys.
        for index, part in enumerate(parsed.search.removeprefix("?").split("&")):
            if not part:
                continue
            try:
                for key, values in parse_search_params("?" + part).items():
                    query.setdefault(key, []).extend(values)
            except (UnicodeDecodeError, ValueError) as exc:
                query_status = "partial"
                query_errors.append({"index": index, "raw_component": part,
                                     "error_type": type(exc).__name__, "message": str(exc)})

    # host_type이 IP면 tldextract 결과는 비어있는 게 정상 (그룹 A-2/A-3/E-1/E-5에서
    # 개별적으로 "해당없음" 처리하므로 여기서는 그대로 둔다)
    ext = _tldextract(parsed.hostname)
    extracted = ExtractedDomain(
        subdomain=ext.subdomain,
        domain=ext.domain,
        suffix=ext.suffix,
        # registered_domain 프로퍼티는 최신 tldextract에서 deprecated됨 →
        # top_domain_under_public_suffix로 대체 (동작은 동일)
        registered_domain=ext.top_domain_under_public_suffix,
    )

    return ParseResult(
        raw_url=raw_url,
        parse_status=ParseStatus.SUCCESS,
        parsed=parsed,
        query=query,
        query_status=query_status,
        query_errors=query_errors,
        extracted=extracted,
        **common,
    )

if __name__ == "__main__":
    import json

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    test_urls = [
        "https://user:pass@www.GOoglé.com:8080/a/../b?q=1#frag",
        "http://300.300.1.1/",  # 구조적 무효 URL
        "http://124.11.1.1/",
        "http://[1:a::g]/",
        "https://blog.sub.naver.co.kr:8080/path/view.php?id=1",
        "",  # 빈 입력
    ]

    for u in test_urls:
        result = parse_url_stage(u)
        print(f"\n입력: {u!r}")
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
