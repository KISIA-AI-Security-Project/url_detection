from __future__ import annotations

from L3_SCANNER.parsers.html_parser import parse_html


def test_parser_builds_form_associations_and_stable_ids() -> None:
    raw = parse_html(
        """
        <form id="login"><input id="password" type="password"></form>
        <form id="profile"></form>
        <input id="email" type="email" form="profile">
        <input id="loose">
        """,
        "https://www.example.com/account",
    )
    assert [form["form_id"] for form in raw["forms"]] == ["login", "profile"]
    assert raw["forms"][0]["input_ids"] == ["password"]
    assert raw["forms"][1]["input_ids"] == ["email"]
    assert [field["form_id"] for field in raw["inputs"]] == ["login", "profile", None]


def test_duplicate_html_ids_fall_back_to_deterministic_internal_ids() -> None:
    raw = parse_html(
        '<form id="duplicate"></form><form id="duplicate"><input id="x"></form>',
        "https://www.example.com/",
    )
    assert [form["form_id"] for form in raw["forms"]] == ["form-1", "form-2"]
    assert raw["inputs"][0]["form_id"] == "form-2"


def test_valid_base_is_applied_consistently_to_urls() -> None:
    raw = parse_html(
        """
        <base href="https://assets.example.net/root/">
        <form action="submit"></form>
        <img src="images/logo.png">
        <link rel="icon" href="favicon.ico">
        <meta property="og:image" content="share.png">
        <meta http-equiv="refresh" content="0; URL='next'">
        <script src="app.js"></script>
        """,
        "https://www.example.com/page/index.html",
    )
    assert raw["forms"][0]["action_url"] == "https://assets.example.net/root/submit"
    assert (
        raw["images"][0]["resource_url"]
        == "https://assets.example.net/root/images/logo.png"
    )
    assert (
        raw["favicon"]["resource_url"] == "https://assets.example.net/root/favicon.ico"
    )
    assert (
        raw["open_graph"]["og:image"]["resource_url"]
        == "https://assets.example.net/root/share.png"
    )
    assert raw["meta_refresh"]["target_url"] == "https://assets.example.net/root/next"
    assert raw["scripts"][0]["source_url"] == "https://assets.example.net/root/app.js"


def test_missing_and_empty_form_actions_are_distinct_and_same_document() -> None:
    raw = parse_html(
        "<form></form><form action=''></form>",
        "https://www.example.com/path/page",
    )
    assert raw["forms"][0]["action_resolution"] == "implicit_document"
    assert raw["forms"][1]["action_resolution"] == "empty_document"
    assert {form["action_url"] for form in raw["forms"]} == {
        "https://www.example.com/path/page"
    }


def test_meta_refresh_parses_valid_and_preserves_malformed_observation() -> None:
    valid = parse_html(
        '<meta http-equiv="REFRESH" content="2.5; url=/login">',
        "https://www.example.com/start",
    )
    malformed = parse_html(
        '<meta http-equiv="refresh" content="immediately; url=/login">',
        "https://www.example.com/start",
    )
    assert valid["meta_refresh"]["valid"] is True
    assert valid["meta_refresh"]["delay_seconds"] == 2.5
    assert valid["meta_refresh"]["target_url"] == "https://www.example.com/login"
    assert malformed["meta_refresh"]["valid"] is False
    assert malformed["meta_refresh"]["raw_content"] == "immediately; url=/login"


def test_malformed_but_parseable_html_preserves_form_structure() -> None:
    raw = parse_html(
        "<form id=login><input name=user><input name=pass", "https://www.example.com/"
    )
    assert raw["document"]["parse_succeeded"] is True
    assert raw["forms"][0]["input_ids"] == ["input-1", "input-2"]


def test_missing_html_is_a_structured_parse_failure() -> None:
    raw = parse_html(None, "https://www.example.com/")
    assert raw["document"]["parse_succeeded"] is False
    assert raw["errors"][0]["code"] == "missing_html"


def test_document_hash_size_and_truncation_state_are_preserved() -> None:
    raw = parse_html("<p>partial", "https://www.example.com/", truncated=True)
    assert raw["document"]["size"] == len("<p>partial".encode())
    assert len(raw["document"]["sha256"]) == 64
    assert raw["document"]["source_complete"] is False
    assert raw["errors"][0]["code"] == "html_source_truncated"


def test_parser_preserves_inline_and_external_script_contract_without_fetching() -> (
    None
):
    raw = parse_html(
        '<script>const value = 1;</script><script src="https://cdn.example.net/app.js"></script>',
        "https://www.example.com/",
    )
    inline, external = raw["scripts"]
    assert inline["type"] == "inline"
    assert inline["source"] == "const value = 1;"
    assert len(inline["sha256"]) == 64
    assert inline["size"] == len(inline["source"].encode())
    assert external["type"] == "external"
    assert external["source_url"] == "https://cdn.example.net/app.js"
    assert external["source"] is None
    assert external["sha256"] is None


def test_non_http_and_malformed_urls_remain_unresolved() -> None:
    raw = parse_html(
        '<base href="javascript:alert(1)"><form action="javascript:send()"></form><img src="http://[bad">',
        "https://www.example.com/",
    )
    assert raw["base"]["valid"] is False
    assert raw["forms"][0]["action_url"] is None
    assert raw["images"][0]["resource_url"] is None
