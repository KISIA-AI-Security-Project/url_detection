"""일관된 HTTP(S) URL 해석과 PSL 기반 등록 도메인 처리.

모든 Parser와 Analyzer가 같은 URL 기준을 사용하도록 이 모듈에 정규화를 모은다.
단순히 마지막 두 라벨을 자르지 않으며 IP 주소를 가짜 eTLD+1로 만들지 않는다.
"""

from __future__ import annotations

import ipaddress
from typing import cast
from urllib.parse import urljoin, urlsplit

import tldextract

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def is_http_url(value: str | None) -> bool:
    """값이 호스트를 가진 절대 HTTP(S) URL인지 안전하게 확인한다."""
    if not value:
        return False
    try:
        parts = urlsplit(value)
        return parts.scheme.lower() in {"http", "https"} and bool(parts.hostname)
    except ValueError:
        return False


def resolve_http_url(value: str | None, base_url: str) -> str | None:
    """상대 참조를 기준 URL로 해석하고 HTTP(S) URL만 반환한다."""
    if value is None:
        return None
    try:
        resolved = urljoin(base_url, value.strip())
    except ValueError:
        return None
    return resolved if is_http_url(resolved) else None


def etld1(value: str | None) -> str | None:
    """URL 호스트의 PSL 기반 eTLD+1을 반환한다.

    URL이 아니거나 IP literal인 경우 비교 가능한 등록 도메인이 없으므로 ``None``을
    반환한다. 이 ``None``은 Analyzer에서 '외부가 아님'으로 해석하면 안 된다.
    """
    if not is_http_url(value):
        return None
    try:
        hostname = cast(str | None, urlsplit(value).hostname)
        if hostname is None:
            return None
        ipaddress.ip_address(hostname)
        return None
    except ValueError:
        pass
    assert hostname is not None
    extracted = _EXTRACT(hostname)
    # tldextract 5.2에서 속성명이 변경되었지만 PSL 의미는 동일하다. 저장소가
    # 사용하는 버전과 최신 런타임을 모두 지원해 환경에 따른 도메인 차이를 막는다.
    registered = getattr(extracted, "top_domain_under_public_suffix", None)
    if registered is None:
        registered = extracted.registered_domain
    return registered or None
