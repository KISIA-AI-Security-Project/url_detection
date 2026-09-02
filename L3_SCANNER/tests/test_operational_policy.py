from __future__ import annotations

import json
import sys
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest

import L3_SCANNER.main as main_module
from L3_SCANNER.analyzers.html import (
    brand_domain_mismatch,
    brand_resource_mismatch,
    credential_field,
)
from L3_SCANNER.output import output_paths
from L3_SCANNER.parsers.html_parser import parse_html
from L3_SCANNER.policies.operational import (
    DEFAULT_OPERATIONAL_POLICY_NAME,
    DEFAULT_OPERATIONAL_POLICY_RESOURCE,
    PolicyConfigurationError,
    load_operational_policy_config,
    operational_detection_policy,
)


def _custom_policy(tmp_path: Path) -> Path:
    resource = files("L3_SCANNER.policies").joinpath(
        DEFAULT_OPERATIONAL_POLICY_RESOURCE
    )
    value = json.loads(resource.read_text(encoding="utf-8"))
    value["policy_name"] = "tenant-operational-v1"
    value["brands"] = {
        "ExampleBank": {
            "title_tokens": ["ExampleBank"],
            "site_name_tokens": ["Example Bank"],
            "hostname_tokens": ["examplebank", "example-bank"],
            "expected_domains": ["examplebank.com"],
            "resource_domains": ["examplebank-cdn.com"],
        }
    }
    value["brand_resources"]["shared_domains"] = ["shared-cdn.com"]
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_bundled_operational_policy_configures_generic_fields() -> None:
    config = load_operational_policy_config()
    policy = operational_detection_policy()

    assert config.policy_name == DEFAULT_OPERATIONAL_POLICY_NAME
    assert config.brands == {}
    assert policy.policy_name == DEFAULT_OPERATIONAL_POLICY_NAME
    assert policy.credential_classifier is not None
    assert policy.brand_identifier is not None
    assert policy.brand_expected_domains == {}
    assert policy.brand_resource_rules is not None
    assert policy.dynamic_execution_apis == frozenset({"eval", "Function"})
    assert policy.network_apis is not None
    assert policy.branch_behavior_normalizer is not None


def test_operational_credential_policy_uses_structural_attributes() -> None:
    raw = parse_html(
        """
        <input id="account-email" type="text" autocomplete="email">
        <input name="user_name" type="text">
        <input placeholder="Account passcode" type="text">
        <input id="search" type="search">
        """,
        "https://example.com/",
    )

    result = credential_field.analyze(
        raw,
        "https://example.com/",
        operational_detection_policy(),
    )

    assert result["detected"] is True
    assert result["evidence"]["field_types"] == ["email", "password", "username"]
    assert result["evidence"]["field_count"] == 3


def test_unconfigured_brand_remains_unresolved() -> None:
    raw = parse_html(
        '<title>Unknown</title><img src="https://cdn.example.net/a.png">',
        "https://example.com/",
    )
    policy = operational_detection_policy()

    domain = brand_domain_mismatch.analyze(raw, "https://example.com/", policy)
    resource = brand_resource_mismatch.analyze(raw, "https://example.com/", policy)

    assert domain["detected"] is None
    assert resource["detected"] is None


def test_custom_brand_policy_controls_domain_and_resource_matching(
    tmp_path: Path,
) -> None:
    policy = operational_detection_policy(_custom_policy(tmp_path))
    raw = parse_html(
        """
        <title>ExampleBank secure login</title>
        <img src="https://examplebank-cdn.com/logo.png">
        <img src="https://evil.example.net/copy.png">
        """,
        "https://phishing-example.net/",
    )

    domain = brand_domain_mismatch.analyze(raw, "https://phishing-example.net/", policy)
    resource = brand_resource_mismatch.analyze(
        raw, "https://phishing-example.net/", policy
    )

    assert policy.policy_name == "tenant-operational-v1"
    assert domain["detected"] is True
    assert domain["evidence"]["expected_domains"] == ["examplebank.com"]
    assert domain["evidence"]["brand_identification_sources"] == ["title"]
    assert domain["evidence"]["brand_identification_confidence"] == "high"
    assert resource["detected"] is True


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://examplebank-secure.com/login", True),
        ("https://login-example-bank.com/", True),
        ("https://examplebank.verify-login.net/", True),
        ("https://myexamplebanking.com/", None),
        ("https://unrelated.example.com/examplebank/login", None),
        ("https://unrelated.example.com/?brand=examplebank", None),
        ("https://login.examplebank.com/", False),
    ],
)
def test_hostname_brand_tokens_use_label_boundaries_and_ignore_path_query(
    tmp_path: Path, url: str, expected: bool | None
) -> None:
    policy = operational_detection_policy(_custom_policy(tmp_path))
    raw = parse_html("<p>neutral</p>", url)

    result = brand_domain_mismatch.analyze(raw, url, policy)

    assert result["detected"] is expected
    if expected is not None:
        assert result["evidence"]["brand_identification_sources"] == ["hostname"]
        assert result["evidence"]["brand_identification_confidence"] == "low"


def test_operational_policy_rejects_unknown_fields(tmp_path: Path) -> None:
    path = _custom_policy(tmp_path)
    value = json.loads(path.read_text(encoding="utf-8"))
    value["unexpected"] = True
    path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(PolicyConfigurationError, match="unknown fields"):
        operational_detection_policy(path)


def test_main_uses_operational_policy_external_scripts_and_split_output(
    monkeypatch: Any, tmp_path: Path
) -> None:
    observed: dict[str, Any] = {}
    output = tmp_path / "nested" / "result.json"

    def fake_scan_url(url: str, *, policy: Any, runtime: Any) -> dict[str, Any]:
        observed.update(url=url, policy=policy, runtime=runtime)
        return {
            "schema_version": "1.0",
            "layer": "L3",
            "target": {"original_url": url, "document_url": url},
            "scan": {
                "status": "completed",
                "policy_name": policy.policy_name,
            },
            "raw": {"html": {"forms": []}, "javascript": {"scripts": []}},
            "signals": [{"id": "L3-H-01", "detected": False}],
            "errors": [],
        }

    monkeypatch.setattr(main_module, "scan_url", fake_scan_url)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "L3_SCANNER.main",
            "--fetch-external-scripts",
            "--output",
            str(output),
            "https://example.com",
        ],
    )

    main_module.main()

    assert observed["url"] == "https://example.com"
    assert observed["policy"].policy_name == DEFAULT_OPERATIONAL_POLICY_NAME
    assert observed["runtime"].fetch_external_scripts is True
    assert not output.exists()

    raw_output = output.with_name("result_raw.json")
    signals_output = output.with_name("result_signals.json")
    raw_document = json.loads(raw_output.read_text(encoding="utf-8"))
    signals_document = json.loads(signals_output.read_text(encoding="utf-8"))

    assert raw_document["scan"]["policy_name"] == DEFAULT_OPERATIONAL_POLICY_NAME
    assert "signals" not in raw_document
    assert signals_document["signals"][0]["id"] == "L3-H-01"
    assert "raw" not in signals_document


def test_output_paths_add_json_extension_when_base_has_no_suffix() -> None:
    raw_path, signals_path = output_paths(Path("results/l3"))

    assert raw_path == Path("results/l3_raw.json")
    assert signals_path == Path("results/l3_signals.json")
