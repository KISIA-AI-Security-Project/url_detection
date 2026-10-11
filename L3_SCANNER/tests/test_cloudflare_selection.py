from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
import sys
from typing import Iterable
import httpx
import pytest

import L3_SCANNER.brands.main as brand_main_module
from L3_SCANNER.brands.cloudflare import (
    CloudflareRankingConfig,
    CloudflareRankingError,
    RankedDomain,
    fetch_cloudflare_top_domains,
)
from L3_SCANNER.brands.wikidata import (
    WikidataBrandCache,
    WikidataSelection,
    WikidataSyncConfig,
    load_wikidata_brand_cache,
    sync_ranked_domains_to_wikidata_cache,
    write_wikidata_brand_cache,
)
from L3_SCANNER.policies.operational import operational_detection_policy


def test_cloudflare_top_domains_are_authenticated_ordered_and_normalized() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer secret-token"
        assert request.url.params["limit"] == "3"
        return httpx.Response(
            200,
            json={
                "success": True,
                "errors": [],
                "result": {
                    "top_0": [
                        {"rank": 2, "domain": "www.Example.com"},
                        {"rank": 1, "domain": "google.com"},
                        {"rank": 3, "domain": "example.com"},
                    ]
                },
            },
        )

    result = fetch_cloudflare_top_domains(
        "secret-token",
        CloudflareRankingConfig(limit=3),
        transport=httpx.MockTransport(handler),
    )

    assert result == (
        RankedDomain(rank=1, domain="google.com"),
        RankedDomain(rank=2, domain="example.com"),
    )


def test_cloudflare_ranking_is_bounded_and_rejects_unordered_range() -> None:
    with pytest.raises(CloudflareRankingError, match="between 1 and 100"):
        CloudflareRankingConfig(limit=101)

    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            json={"success": True, "result": {"top_0": [{"padding": "x" * 100}]}},
        )
    )
    with pytest.raises(CloudflareRankingError, match="max_response_bytes"):
        fetch_cloudflare_top_domains(
            "secret-token",
            CloudflareRankingConfig(limit=1, max_response_bytes=20),
            transport=transport,
        )


def _wikidata_transport(official_url: str) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        params = request.url.params
        if params["action"] == "wbsearchentities":
            query = params["search"]
            return httpx.Response(
                200,
                json={
                    "search": [
                        {
                            "id": "Q123",
                            "label": "ExampleBank",
                            "match": {"type": "alias", "text": query},
                        }
                    ]
                },
            )
        return httpx.Response(
            200,
            json={
                "entities": {
                    "Q123": {
                        "id": "Q123",
                        "lastrevid": 789,
                        "labels": {"en": {"language": "en", "value": "ExampleBank"}},
                        "aliases": {
                            "en": [
                                {
                                    "language": "en",
                                    "value": "examplebank.com",
                                }
                            ]
                        },
                        "claims": {
                            "P856": [
                                {
                                    "rank": "normal",
                                    "mainsnak": {
                                        "snaktype": "value",
                                        "datavalue": {
                                            "value": official_url,
                                            "type": "string",
                                        },
                                    },
                                }
                            ]
                        },
                    }
                }
            },
        )

    return httpx.MockTransport(handler)


def test_ranked_domain_requires_matching_wikidata_p856_and_preserves_selection(
    tmp_path: Path,
) -> None:
    cache = sync_ranked_domains_to_wikidata_cache(
        [RankedDomain(rank=7, domain="examplebank.com")],
        WikidataSyncConfig(languages=("en",)),
        transport=_wikidata_transport("https://www.examplebank.com/home"),
        now=datetime(2026, 9, 2, tzinfo=UTC),
    )

    assert cache.selection is not None
    assert cache.selection.provider == "cloudflare_radar"
    assert cache.selection.requested_limit == 1
    assert cache.unresolved == ()
    assert cache.brands[0].label == "ExampleBank"
    assert cache.brands[0].selection_domain == "examplebank.com"
    assert cache.brands[0].selection_rank == 7

    path = tmp_path / "ranked-cache.json"
    write_wikidata_brand_cache(path, cache)
    loaded = load_wikidata_brand_cache(path)
    policy = operational_detection_policy(wikidata_cache_path=path)

    assert loaded == cache
    assert policy.brand_policy_metadata is not None
    assert policy.brand_policy_metadata["selection"] == {
        "provider": "cloudflare_radar",
        "dataset": "domain_ranking_top",
        "requested_limit": 1,
    }


def test_ranked_domain_without_matching_p856_stays_unresolved() -> None:
    cache = sync_ranked_domains_to_wikidata_cache(
        [RankedDomain(rank=1, domain="examplebank.com")],
        WikidataSyncConfig(languages=("en",)),
        transport=_wikidata_transport("https://different-bank.com"),
        now=datetime(2026, 9, 2, tzinfo=UTC),
    )

    assert cache.brands == ()
    assert len(cache.unresolved) == 1
    assert cache.unresolved[0].requested_name == "examplebank.com"
    assert cache.unresolved[0].reason == "no_wikidata_official_domain_match"
    assert cache.unresolved[0].candidate_ids == ("Q123",)


def test_wikidata_cli_uses_cloudflare_token_only_for_selection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    observed: dict[str, object] = {}
    output = tmp_path / "brands.json"

    def fake_fetch(token: str, config: CloudflareRankingConfig):
        observed["token"] = token
        observed["limit"] = config.limit
        return (RankedDomain(rank=1, domain="examplebank.com"),)

    def fake_sync(
        domains: Iterable[RankedDomain], config: WikidataSyncConfig
    ) -> WikidataBrandCache:
        observed["domains"] = tuple(domains)
        return WikidataBrandCache(
            generated_at="2026-09-02T00:00:00Z",
            brands=(),
            unresolved=(),
            selection=WikidataSelection("cloudflare_radar", "domain_ranking_top", 1),
        )

    monkeypatch.setattr(brand_main_module, "fetch_cloudflare_top_domains", fake_fetch)
    monkeypatch.setattr(
        brand_main_module, "sync_ranked_domains_to_wikidata_cache", fake_sync
    )
    monkeypatch.setenv("TEST_CLOUDFLARE_TOKEN", "private-token")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "L3_SCANNER.brands.main",
            "--cloudflare-top-domains",
            "1",
            "--cloudflare-token-env",
            "TEST_CLOUDFLARE_TOKEN",
            "--output",
            str(output),
        ],
    )

    brand_main_module.main()

    assert observed == {
        "token": "private-token",
        "limit": 1,
        "domains": (RankedDomain(rank=1, domain="examplebank.com"),),
    }
    assert "private-token" not in output.read_text(encoding="utf-8")
