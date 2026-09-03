from __future__ import annotations

import pytest

from L3_SCANNER.analyzers.html import (
    base_url_change,
    brand_domain_mismatch,
    brand_resource_mismatch,
    credential_field,
    credential_form,
    external_post,
    form_action_domain,
    html_redirect,
)
from L3_SCANNER.parsers.html_parser import parse_html
from L3_SCANNER.policies.detection import DetectionPolicy

DOCUMENT_URL = "https://login.example.com/account"


def credential_classifier(field: dict[str, object]) -> str | None:
    field_type = field.get("type")
    if field_type in {"password", "email"}:
        return str(field_type)
    if field.get("name") == "username":
        return "username"
    return None


def parsed(html: str, url: str = DOCUMENT_URL):
    return parse_html(html, url)


@pytest.mark.parametrize(
    "analyzer", [credential_form.analyze, credential_field.analyze]
)
def test_credential_signals_do_not_invent_missing_policy(analyzer) -> None:
    result = analyzer(parsed('<form><input type="password"></form>'), DOCUMENT_URL)
    assert result["status"] == "evaluated"
    assert result["detected"] is None


def test_h01_positive_negative_and_unassociated_edge() -> None:
    policy = DetectionPolicy(credential_classifier=credential_classifier)
    positive = credential_form.analyze(
        parsed('<form id="login"><input type="password"></form>'), DOCUMENT_URL, policy
    )
    negative = credential_form.analyze(
        parsed('<form><input type="search"></form>'), DOCUMENT_URL, policy
    )
    unassociated = credential_form.analyze(
        parsed('<input type="password">'), DOCUMENT_URL, policy
    )
    assert positive["detected"] is True
    assert positive["evidence"] == {"form_count": 1, "form_ids": ["login"]}
    assert negative["detected"] is False
    assert unassociated["detected"] is False


def test_h02_positive_negative_and_disabled_readonly_edge() -> None:
    policy = DetectionPolicy(credential_classifier=credential_classifier)
    positive = credential_field.analyze(
        parsed(
            '<input id="mail" type="email" disabled><input id="pass" type="password" readonly>'
        ),
        DOCUMENT_URL,
        policy,
    )
    negative = credential_field.analyze(
        parsed('<input type="search">'), DOCUMENT_URL, policy
    )
    assert positive["detected"] is True
    assert positive["evidence"]["field_types"] == ["email", "password"]
    assert negative["detected"] is False


@pytest.mark.parametrize(
    "analyzer", [credential_form.analyze, credential_field.analyze]
)
def test_credential_signals_return_error_for_missing_html_or_policy_failure(
    analyzer,
) -> None:
    missing = analyzer(
        parse_html(None, DOCUMENT_URL),
        DOCUMENT_URL,
        DetectionPolicy(credential_classifier=credential_classifier),
    )
    broken = analyzer(
        parsed("<input>"),
        DOCUMENT_URL,
        DetectionPolicy(
            credential_classifier=lambda field: (_ for _ in ()).throw(
                RuntimeError("bad policy")
            )
        ),
    )
    assert missing["status"] == "error" and missing["detected"] is None
    assert broken["status"] == "error" and broken["detected"] is None


def test_h03_observes_same_external_and_unresolved_destinations_without_detection_mapping() -> (
    None
):
    raw = parsed(
        """
        <form id="same" action="https://api.example.com/submit"></form>
        <form id="external" action="https://collector.example.net/submit"></form>
        <form id="script" action="javascript:send()"></form>
        """
    )
    result = form_action_domain.analyze(raw, DOCUMENT_URL)
    forms = {item["form_id"]: item for item in result["evidence"]["forms"]}
    assert result["detected"] is None
    assert forms["same"]["domain_match"] is True
    assert forms["external"]["domain_match"] is False
    assert forms["script"]["domain_match"] is None


def test_h03_no_forms_is_not_applicable_and_ip_is_unresolved() -> None:
    empty = form_action_domain.analyze(parsed("<p>none</p>"), DOCUMENT_URL)
    ip = form_action_domain.analyze(
        parsed('<form action="https://127.0.0.1/submit"></form>'), DOCUMENT_URL
    )
    assert empty["status"] == "not_applicable"
    assert ip["evidence"]["domain_match"] is None


def test_h03_parse_error_is_not_negative() -> None:
    result = form_action_domain.analyze(parse_html(None, DOCUMENT_URL), DOCUMENT_URL)
    assert result["status"] == "error" and result["detected"] is None


def test_h04_detects_external_post_and_preserves_credential_relation() -> None:
    result = external_post.analyze(
        parsed(
            '<form id="login" method="POST" action="https://collect.example.net/"><input type="password"></form>'
        ),
        DOCUMENT_URL,
        DetectionPolicy(credential_classifier=credential_classifier),
    )
    assert result["detected"] is True
    assert result["evidence"]["destination_etld1"] == "example.net"
    assert result["evidence"]["credential_form"] is True


def test_h04_same_site_negative_non_post_not_applicable_and_unknown_unresolved() -> (
    None
):
    same = external_post.analyze(
        parsed('<form method="post" action="https://api.example.com/"></form>'),
        DOCUMENT_URL,
    )
    get = external_post.analyze(
        parsed('<form method="get" action="https://example.net/"></form>'), DOCUMENT_URL
    )
    unknown = external_post.analyze(
        parsed('<form method="post" action="javascript:send()"></form>'), DOCUMENT_URL
    )
    assert same["detected"] is False
    assert get["status"] == "not_applicable"
    assert unknown["detected"] is None


def test_h04_external_post_wins_when_another_destination_is_unresolved() -> None:
    result = external_post.analyze(
        parsed(
            '<form method="post" action="javascript:x"></form><form method="post" action="https://example.net/"></form>'
        ),
        DOCUMENT_URL,
    )
    assert result["detected"] is True


def test_h04_parse_error_is_not_negative() -> None:
    result = external_post.analyze(parse_html(None, DOCUMENT_URL), DOCUMENT_URL)
    assert result["status"] == "error" and result["detected"] is None


def brand_identifier(context: dict[str, object]) -> str | None:
    title = context["document"].get("title")  # type: ignore[union-attr]
    return "ExampleBank" if title and "ExampleBank" in title else None


def test_h05_mismatch_match_and_missing_brand_policy() -> None:
    raw = parsed("<title>ExampleBank login</title>")
    mismatch = brand_domain_mismatch.analyze(
        raw,
        DOCUMENT_URL,
        DetectionPolicy(
            brand_identifier=brand_identifier,
            brand_expected_domains={"ExampleBank": ("bank.example.net",)},
        ),
    )
    match = brand_domain_mismatch.analyze(
        raw,
        DOCUMENT_URL,
        DetectionPolicy(
            brand_identifier=brand_identifier,
            brand_expected_domains={"ExampleBank": ("example.com",)},
        ),
    )
    missing = brand_domain_mismatch.analyze(raw, DOCUMENT_URL)
    assert mismatch["detected"] is True
    assert match["detected"] is False
    assert missing["detected"] is None


def test_h05_unidentified_brand_ip_and_policy_error_are_unresolved_or_error() -> None:
    unidentified = brand_domain_mismatch.analyze(
        parsed("<title>Neutral</title>"),
        DOCUMENT_URL,
        DetectionPolicy(brand_identifier=brand_identifier, brand_expected_domains={}),
    )
    ip = brand_domain_mismatch.analyze(
        parsed("<title>ExampleBank</title>", "https://127.0.0.1/"),
        "https://127.0.0.1/",
        DetectionPolicy(
            brand_identifier=brand_identifier,
            brand_expected_domains={"ExampleBank": ("example.com",)},
        ),
    )
    broken = brand_domain_mismatch.analyze(
        parsed("<title>x</title>"),
        DOCUMENT_URL,
        DetectionPolicy(
            brand_identifier=lambda context: (_ for _ in ()).throw(RuntimeError("bad"))
        ),
    )
    assert unidentified["detected"] is None
    assert ip["detected"] is None
    assert broken["status"] == "error"


def test_h05_parse_error_is_not_negative() -> None:
    result = brand_domain_mismatch.analyze(parse_html(None, DOCUMENT_URL), DOCUMENT_URL)
    assert result["status"] == "error" and result["detected"] is None


def test_h06_preserves_resources_without_policy_and_accepts_explicit_policy_evaluator() -> (
    None
):
    raw = parsed(
        '<base href="https://cdn.example.net/"><link rel="icon" href="logo.ico"><img src="hero.png">'
    )
    unresolved = brand_resource_mismatch.analyze(raw, DOCUMENT_URL)
    detected = brand_resource_mismatch.analyze(
        raw,
        DOCUMENT_URL,
        DetectionPolicy(
            brand_resource_rules={
                "evaluator": lambda evidence: any(
                    r["resource_domain"] == "example.net" for r in evidence["resources"]
                )
            }
        ),
    )
    negative = brand_resource_mismatch.analyze(
        raw,
        DOCUMENT_URL,
        DetectionPolicy(brand_resource_rules={"evaluator": lambda evidence: False}),
    )
    assert unresolved["detected"] is None
    assert {r["resource_type"] for r in unresolved["evidence"]["resources"]} == {
        "image",
        "favicon",
    }
    assert detected["detected"] is True
    assert negative["detected"] is False


def test_h06_missing_resource_policy_error_and_parse_error() -> None:
    no_resources = brand_resource_mismatch.analyze(parsed("<p>none</p>"), DOCUMENT_URL)
    broken = brand_resource_mismatch.analyze(
        parsed('<img src="/a.png">'),
        DOCUMENT_URL,
        DetectionPolicy(
            brand_resource_rules={
                "evaluator": lambda evidence: (_ for _ in ()).throw(RuntimeError("bad"))
            }
        ),
    )
    parse_error = brand_resource_mismatch.analyze(
        parse_html(None, DOCUMENT_URL), DOCUMENT_URL
    )
    assert no_resources["detected"] is None
    assert broken["status"] == "error"
    assert parse_error["status"] == "error"


def test_h07_positive_negative_malformed_and_parse_error() -> None:
    positive = html_redirect.analyze(
        parsed('<meta http-equiv="refresh" content="0; url=/next">'), DOCUMENT_URL
    )
    negative = html_redirect.analyze(parsed("<p>none</p>"), DOCUMENT_URL)
    malformed = html_redirect.analyze(
        parsed('<meta http-equiv="refresh" content="now; /next">'), DOCUMENT_URL
    )
    error = html_redirect.analyze(parse_html(None, DOCUMENT_URL), DOCUMENT_URL)
    assert positive["detected"] is True
    assert positive["evidence"]["target_url"] == "https://login.example.com/next"
    assert negative["detected"] is False
    assert malformed["detected"] is False
    assert error["status"] == "error" and error["detected"] is None


def test_h08_external_same_absent_malformed_ip_and_parse_error() -> None:
    external = base_url_change.analyze(
        parsed('<base href="https://cdn.example.net/">'), DOCUMENT_URL
    )
    same = base_url_change.analyze(
        parsed('<base href="https://static.example.com/">'), DOCUMENT_URL
    )
    absent = base_url_change.analyze(parsed("<p>none</p>"), DOCUMENT_URL)
    malformed = base_url_change.analyze(
        parsed('<base href="javascript:x">'), DOCUMENT_URL
    )
    ip = base_url_change.analyze(
        parsed('<base href="https://127.0.0.1/">'), DOCUMENT_URL
    )
    error = base_url_change.analyze(parse_html(None, DOCUMENT_URL), DOCUMENT_URL)
    assert external["detected"] is True and external["evidence"]["external"] is True
    assert same["detected"] is False
    assert absent["detected"] is False
    assert malformed["detected"] is None
    assert ip["detected"] is None
    assert error["status"] == "error" and error["detected"] is None
