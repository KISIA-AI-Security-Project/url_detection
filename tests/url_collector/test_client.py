from __future__ import annotations

from dataclasses import FrozenInstanceError

import httpx
import pytest

from url_collector import CollectionPolicy, collect_url


def policy(**overrides: object) -> CollectionPolicy:
    values: dict[str, object] = {
        "request_timeout_seconds": 2.0,
        "max_redirects": 2,
        "max_body_bytes": 1024,
        "user_agent": "Unified-Collector-Test/1.0",
    }
    values.update(overrides)
    return CollectionPolicy(**values)  # type: ignore[arg-type]


def public_resolver(hostname: str, port: int) -> list[str]:
    del hostname, port
    return ["93.184.216.34"]


def test_collects_one_redirect_journey_and_preserves_exact_response() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        assert request.headers["user-agent"] == "Unified-Collector-Test/1.0"
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": "/final"})
        return httpx.Response(
            200,
            headers={"content-type": "text/html; charset=utf-8", "x-test": "same"},
            content=b"<html>same page</html>",
        )

    snapshot = collect_url(
        "https://example.com/start",
        policy(),
        resolver=public_resolver,
        transport=httpx.MockTransport(handler),
    )

    assert calls == [
        "https://example.com/start",
        "https://example.com/final",
    ]
    assert snapshot.final_url == "https://example.com/final"
    assert snapshot.body == b"<html>same page</html>"
    assert snapshot.content_type == "text/html"
    assert snapshot.header("X-Test") == "same"
    assert snapshot.redirect_chain[0].destination_url == snapshot.final_url
    assert snapshot.collection_errors == ()


def test_blocks_private_initial_target_before_request() -> None:
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200)

    snapshot = collect_url(
        "http://internal.example/",
        policy(),
        resolver=lambda hostname, port: ["127.0.0.1"],
        transport=httpx.MockTransport(handler),
    )

    assert called is False
    assert snapshot.final_url is None
    assert snapshot.collection_errors[0].code == "request_failed"
    assert "non-public" in snapshot.collection_errors[0].message


def test_blocks_private_redirect_target_and_preserves_observed_hop() -> None:
    calls = 0

    def resolver(hostname: str, port: int) -> list[str]:
        del port
        return ["127.0.0.1"] if hostname == "internal.example" else ["93.184.216.34"]

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(302, headers={"location": "http://internal.example/"})

    snapshot = collect_url(
        "https://example.com/",
        policy(),
        resolver=resolver,
        transport=httpx.MockTransport(handler),
    )

    assert calls == 1
    assert snapshot.final_url is None
    assert snapshot.redirect_chain[0].destination_url == "http://internal.example/"
    assert snapshot.collection_errors[0].code == "request_failed"


def test_body_is_truncated_at_explicit_limit() -> None:
    snapshot = collect_url(
        "https://example.com/",
        policy(max_body_bytes=4),
        resolver=public_resolver,
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, content=b"12345678")
        ),
    )

    assert snapshot.body == b"1234"
    assert snapshot.truncated is True
    assert len(snapshot.captured_body_sha256) == 64


def test_redirect_limit_keeps_last_observed_destination_without_requesting_it() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(302, headers={"location": f"/next-{calls}"})

    snapshot = collect_url(
        "https://example.com/start",
        policy(max_redirects=1),
        resolver=public_resolver,
        transport=httpx.MockTransport(handler),
    )

    assert calls == 2
    assert len(snapshot.redirect_chain) == 2
    assert snapshot.collection_errors[0].code == "redirect_limit_exceeded"


def test_snapshot_top_level_fields_are_immutable() -> None:
    snapshot = collect_url(
        "https://example.com/",
        policy(),
        resolver=public_resolver,
        transport=httpx.MockTransport(lambda request: httpx.Response(200)),
    )

    with pytest.raises(FrozenInstanceError):
        snapshot.final_url = "https://changed.example/"  # type: ignore[misc]
