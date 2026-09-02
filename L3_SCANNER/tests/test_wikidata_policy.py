from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest

from L3_SCANNER.analyzers.html import (
    brand_domain_mismatch,
    brand_resource_mismatch,
)
from L3_SCANNER.parsers.html_parser import parse_html
from L3_SCANNER.brands.wikidata import (
    WikidataPolicyError,
    WikidataSyncConfig,
    load_wikidata_brand_cache,
    sync_wikidata_brand_cache,
    write_wikidata_brand_cache,
)
from L3_SCANNER.policies.operational import operational_detection_policy


def _statement(
    url: str,
    *,
    rank: str = "normal",
    end_time: str | None = None,
) -> dict[str, Any]:
    claim: dict[str, Any] = {
        "rank": rank,
        "mainsnak": {
            "snaktype": "value",
            "datavalue": {"value": url, "type": "string"},
        },
    }
    if end_time is not None:
        claim["qualifiers"] = {
            "P582": [
                {
                    "datavalue": {
                        "value": {"time": end_time, "precision": 11},
                        "type": "time",
                    }
                }
            ]
        }
    return claim


def _resolved_transport() -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        params = request.url.params
        if params["action"] == "wbsearchentities":
            return httpx.Response(
                200,
                json={
                    "search": [
                        {
                            "id": "Q123",
                            "label": "ExampleBank",
                            "match": {"type": "label", "text": "ExampleBank"},
                        }
                    ]
                },
            )
        assert params["action"] == "wbgetentities"
        return httpx.Response(
            200,
            json={
                "entities": {
                    "Q123": {
                        "id": "Q123",
                        "lastrevid": 456,
                        "labels": {
                            "ko": {"language": "ko", "value": "예시은행"},
                            "en": {"language": "en", "value": "ExampleBank"},
                        },
                        "aliases": {
                            "en": [{"language": "en", "value": "Example Bank"}]
                        },
                        "claims": {
                            "P856": [
                                _statement(
                                    "https://old.examplebank.net",
                                    end_time="+2020-01-01T00:00:00Z",
                                ),
                                _statement("https://www.examplebank.com/home"),
                                _statement(
                                    "https://deprecated.example.org", rank="deprecated"
                                ),
                            ]
                        },
                    }
                }
            },
        )

    return httpx.MockTransport(handler)


def test_wikidata_sync_builds_cache_and_filters_former_domains() -> None:
    cache = sync_wikidata_brand_cache(
        ["ExampleBank", "examplebank"],
        WikidataSyncConfig(languages=("ko", "en")),
        transport=_resolved_transport(),
        now=datetime(2026, 9, 2, tzinfo=UTC),
    )

    assert cache.generated_at == "2026-09-02T00:00:00Z"
    assert len(cache.brands) == 1
    assert cache.unresolved == ()
    brand = cache.brands[0]
    assert brand.entity_id == "Q123"
    assert brand.revision_id == 456
    assert brand.label == "예시은행"
    assert brand.expected_domains == ("examplebank.com",)
    assert "ExampleBank" in brand.aliases
    assert "Example Bank" in brand.aliases


def test_ambiguous_wikidata_name_is_preserved_as_unresolved() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["action"] == "wbsearchentities"
        return httpx.Response(
            200,
            json={
                "search": [
                    {
                        "id": "Q1",
                        "label": "SameBrand",
                        "match": {"text": "SameBrand"},
                    },
                    {
                        "id": "Q2",
                        "label": "SameBrand",
                        "match": {"text": "SameBrand"},
                    },
                ]
            },
        )

    cache = sync_wikidata_brand_cache(
        ["SameBrand"],
        WikidataSyncConfig(languages=("en",)),
        transport=httpx.MockTransport(handler),
        now=datetime(2026, 9, 2, tzinfo=UTC),
    )

    assert cache.brands == ()
    assert cache.unresolved[0].reason == "ambiguous"
    assert cache.unresolved[0].candidate_ids == ("Q1", "Q2")


def test_wikidata_sync_bounds_response_size() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, json={"search": [{"padding": "x" * 50}]})
    )

    with pytest.raises(WikidataPolicyError, match="max_response_bytes"):
        sync_wikidata_brand_cache(
            ["ExampleBank"],
            WikidataSyncConfig(languages=("en",), max_response_bytes=20),
            transport=transport,
            now=datetime(2026, 9, 2, tzinfo=UTC),
        )


def test_wikidata_cache_drives_h05_without_enabling_unknown_h06(
    tmp_path: Path,
) -> None:
    cache = sync_wikidata_brand_cache(
        ["ExampleBank"],
        WikidataSyncConfig(languages=("ko", "en")),
        transport=_resolved_transport(),
        now=datetime(2026, 9, 2, tzinfo=UTC),
    )
    path = tmp_path / "wikidata-brands.json"
    write_wikidata_brand_cache(path, cache)
    policy = operational_detection_policy(wikidata_cache_path=path)
    raw = parse_html(
        """
        <title>ExampleBank Login</title>
        <img src="https://unknown-cdn.example.net/logo.png">
        """,
        "https://examplebank-secure.com/login",
    )

    domain = brand_domain_mismatch.analyze(
        raw, "https://examplebank-secure.com/login", policy
    )
    resource = brand_resource_mismatch.analyze(
        raw, "https://examplebank-secure.com/login", policy
    )

    assert domain["detected"] is True
    assert domain["evidence"]["detected_brand"] == "예시은행"
    assert domain["evidence"]["expected_domains"] == ["examplebank.com"]
    assert domain["evidence"]["brand_policy_provider"] == "wikidata"
    assert domain["evidence"]["brand_policy_entity_id"] == "Q123"
    assert resource["detected"] is None
    assert policy.brand_policy_metadata == {
        "provider": "wikidata",
        "schema_version": "1.0",
        "generated_at": "2026-09-02T00:00:00Z",
        "resolved_brand_count": 1,
        "unresolved_brand_count": 0,
        "selection": None,
    }


def test_wikidata_h06_can_confirm_resources_on_official_domain(tmp_path: Path) -> None:
    cache = sync_wikidata_brand_cache(
        ["ExampleBank"],
        WikidataSyncConfig(languages=("ko", "en")),
        transport=_resolved_transport(),
        now=datetime(2026, 9, 2, tzinfo=UTC),
    )
    path = tmp_path / "wikidata-brands.json"
    write_wikidata_brand_cache(path, cache)
    policy = operational_detection_policy(wikidata_cache_path=path)
    raw = parse_html(
        '<title>ExampleBank</title><img src="https://img.examplebank.com/a.png">',
        "https://examplebank.com/",
    )

    result = brand_resource_mismatch.analyze(raw, "https://examplebank.com/", policy)

    assert result["detected"] is False


def test_wikidata_cache_rejects_other_providers_and_mixed_brand_sources(
    tmp_path: Path,
) -> None:
    cache_path = tmp_path / "cache.json"
    cache_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "provider": "other",
                "generated_at": "2026-09-02T00:00:00Z",
                "brands": [],
                "unresolved": [],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(WikidataPolicyError, match="provider must be wikidata"):
        load_wikidata_brand_cache(cache_path)

    valid_cache = sync_wikidata_brand_cache(
        ["ExampleBank"],
        WikidataSyncConfig(languages=("ko", "en")),
        transport=_resolved_transport(),
        now=datetime(2026, 9, 2, tzinfo=UTC),
    )
    write_wikidata_brand_cache(cache_path, valid_cache)
    policy_path = tmp_path / "manual-policy.json"
    bundled = Path(__file__).parents[1] / "policies" / "operational.v1.json"
    policy_value = json.loads(bundled.read_text(encoding="utf-8"))
    policy_value["brands"] = {
        "Manual": {
            "title_tokens": ["Manual"],
            "site_name_tokens": [],
            "hostname_tokens": ["manual"],
            "expected_domains": ["manual.com"],
            "resource_domains": [],
        }
    }
    policy_path.write_text(json.dumps(policy_value), encoding="utf-8")

    with pytest.raises(
        ValueError, match="brands and shared resource domains must be empty"
    ):
        operational_detection_policy(policy_path, cache_path)
