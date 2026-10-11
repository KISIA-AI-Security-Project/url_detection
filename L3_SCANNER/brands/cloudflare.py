"""Cloudflare Radar 상위 Domain을 브랜드 정책 후보로 제한 수집한다.

이 데이터는 조회 우선순위만 제공한다. 브랜드명과 공식 Domain의 최종 정책 원천은
Wikidata이며, Cloudflare 결과만으로 H-05/H-06 판단을 만들지 않는다.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping

import httpx

from L3_SCANNER.utils.url import etld1

CLOUDFLARE_DOMAIN_RANKING_URL = "https://api.cloudflare.com/client/v4/radar/ranking/top"


class CloudflareRankingError(ValueError):
    """Cloudflare Ranking 설정이나 응답이 지원 계약을 위반했음을 나타낸다."""


@dataclass(frozen=True, slots=True)
class CloudflareRankingConfig:
    """정확한 순서가 제공되는 상위 100 Domain 조회의 네트워크 제한."""

    api_url: str = CLOUDFLARE_DOMAIN_RANKING_URL
    limit: int = 100
    request_timeout_seconds: float = 10.0
    max_response_bytes: int = 1_000_000
    user_agent: str = "L3-Scanner/0.1 (Cloudflare Radar brand selection)"

    def __post_init__(self) -> None:
        if self.api_url != CLOUDFLARE_DOMAIN_RANKING_URL:
            raise CloudflareRankingError(
                "only the official Cloudflare Radar API is supported"
            )
        if not 1 <= self.limit <= 100:
            raise CloudflareRankingError(
                "limit must be between 1 and 100 for ordered domain rankings"
            )
        if self.request_timeout_seconds <= 0:
            raise CloudflareRankingError("request_timeout_seconds must be positive")
        if self.max_response_bytes <= 0:
            raise CloudflareRankingError("max_response_bytes must be positive")
        if not self.user_agent.strip():
            raise CloudflareRankingError("user_agent must not be empty")


@dataclass(frozen=True, slots=True)
class RankedDomain:
    """Cloudflare가 제공한 순위와 PSL 정규화 Domain."""

    rank: int
    domain: str


def _response_json(
    client: httpx.Client, config: CloudflareRankingConfig
) -> Mapping[str, Any]:
    body = bytearray()
    with client.stream(
        "GET",
        config.api_url,
        params={"name": "top", "limit": config.limit},
    ) as response:
        response.raise_for_status()
        for chunk in response.iter_bytes():
            if len(body) + len(chunk) > config.max_response_bytes:
                raise CloudflareRankingError(
                    "Cloudflare response exceeded configured max_response_bytes"
                )
            body.extend(chunk)
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CloudflareRankingError("Cloudflare returned invalid JSON") from exc
    if not isinstance(value, Mapping):
        raise CloudflareRankingError("Cloudflare returned a non-object response")
    if value.get("success") is not True:
        raise CloudflareRankingError(
            f"Cloudflare API returned an unsuccessful response: {value.get('errors')}"
        )
    return value


def fetch_cloudflare_top_domains(
    api_token: str,
    config: CloudflareRankingConfig | None = None,
    *,
    transport: httpx.BaseTransport | None = None,
) -> tuple[RankedDomain, ...]:
    """상위 Domain을 인증 토큰 노출 없이 조회하고 eTLD+1로 정규화한다."""
    if not api_token.strip():
        raise CloudflareRankingError("Cloudflare API token must not be empty")
    active_config = config or CloudflareRankingConfig()
    with httpx.Client(
        timeout=active_config.request_timeout_seconds,
        transport=transport,
        trust_env=False,
        headers={
            "Authorization": f"Bearer {api_token}",
            "User-Agent": active_config.user_agent,
            "Accept-Encoding": "gzip, deflate",
        },
    ) as client:
        value = _response_json(client, active_config)
    result = value.get("result")
    if not isinstance(result, Mapping):
        raise CloudflareRankingError("Cloudflare result is missing")
    entries = result.get("top_0")
    if not isinstance(entries, list):
        raise CloudflareRankingError("Cloudflare top_0 ranking is missing")

    ranked: list[RankedDomain] = []
    seen_domains: set[str] = set()
    for item in entries:
        if not isinstance(item, Mapping):
            continue
        rank = item.get("rank")
        domain_value = item.get("domain")
        if (
            not isinstance(rank, int)
            or isinstance(rank, bool)
            or rank <= 0
            or not isinstance(domain_value, str)
        ):
            continue
        domain = etld1(f"https://{domain_value.strip().lower().rstrip('.')}")
        if domain is None or domain in seen_domains:
            continue
        seen_domains.add(domain)
        ranked.append(RankedDomain(rank=rank, domain=domain))
    ranked.sort(key=lambda item: item.rank)
    if not ranked:
        raise CloudflareRankingError("Cloudflare ranking contained no valid domains")
    return tuple(ranked[: active_config.limit])
