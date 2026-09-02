"""Base URL과 Meta Refresh 기반 이동의 Raw Observation Builder."""

import math
import re
from typing import Any

from bs4 import BeautifulSoup, Tag

from L3_SCANNER.utils.url import etld1, resolve_http_url

_REFRESH_RE = re.compile(
    r"^\s*(?P<delay>(?:\d+(?:\.\d*)?|\.\d+))\s*"
    r"(?:;\s*(?:url\s*=\s*)?(?P<url>.+?)\s*)?$",
    re.IGNORECASE,
)


def apply_base(raw: dict[str, Any], soup: BeautifulSoup, document_url: str) -> str:
    """첫 번째 유효한 ``<base href>``를 기록하고 후속 URL의 기준을 반환한다.

    브라우저와 마찬가지로 첫 번째 base 요소만 사용한다. 유효하지 않은 href도 Raw에
    남기되 실제 이미지·폼·스크립트 URL 해석 기준은 문서 URL을 유지한다.
    """
    effective_base = document_url
    first_base = soup.find("base", href=True)
    if isinstance(first_base, Tag):
        href = str(first_base.get("href") or "").strip()
        resolved = resolve_http_url(href, document_url) if href else None
        raw["base"] = {
            "raw_href": href,
            "base_url": resolved,
            "base_etld1": etld1(resolved),
            "valid": resolved is not None,
        }
        if resolved is not None:
            effective_base = resolved
    raw["document"]["effective_base_url"] = effective_base
    return effective_base


def build_meta_refresh(
    raw: dict[str, Any], soup: BeautifulSoup, effective_base: str
) -> None:
    """첫 Meta Refresh 요소를 찾아 구조화된 이동 관측값을 저장한다."""
    refresh = soup.find(
        "meta",
        attrs={
            "http-equiv": lambda value: bool(
                value and str(value).strip().lower() == "refresh"
            )
        },
    )
    if isinstance(refresh, Tag):
        raw["meta_refresh"] = _parse_refresh(
            str(refresh.get("content") or ""), effective_base
        )


def _parse_refresh(content: str, base_url: str) -> dict[str, Any]:
    """Meta Refresh의 지연시간과 선택적 목적지를 보수적으로 파싱한다.

    형식이 잘못됐거나 HTTP(S)가 아닌 목적지는 ``valid=False``로 남긴다. 원문과
    해석 가능한 일부 값은 보존해 정책 또는 후속 분석이 재사용할 수 있게 한다.
    """
    result: dict[str, Any] = {
        "raw_content": content,
        "valid": False,
        "delay_seconds": None,
        "target_raw": None,
        "target_url": None,
    }
    match = _REFRESH_RE.fullmatch(content)
    if match is None:
        return result
    delay = float(match.group("delay"))
    if not math.isfinite(delay):
        return result
    target = match.group("url")
    if target is not None:
        target = target.strip().strip("\"'").strip()
        if not target:
            return result
        target_url = resolve_http_url(target, base_url)
        if target_url is None:
            result["target_raw"] = target
            return result
        result["target_raw"] = target
        result["target_url"] = target_url
    result["valid"] = True
    result["delay_seconds"] = delay
    return result
