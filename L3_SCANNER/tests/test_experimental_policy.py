from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import L3_SCANNER.main as main_module
from L3_SCANNER.policies.experimental import experimental_detection_policy


def test_experimental_policy_configures_every_open_policy_field() -> None:
    policy = experimental_detection_policy()

    assert policy.credential_classifier is not None
    assert policy.brand_identifier is not None
    assert policy.brand_expected_domains is not None
    assert policy.brand_resource_rules is not None
    assert policy.dynamic_execution_apis is not None
    assert policy.decode_methods is not None
    assert policy.network_apis is not None
    assert policy.redirect_apis is not None
    assert policy.anti_bot_properties is not None
    assert policy.branch_behavior_normalizer is not None


def test_main_all_enables_policy_external_scripts_and_output(
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
            "scan": {"status": "completed"},
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
            "--all",
            "--output",
            str(output),
            "https://example.com",
        ],
    )

    main_module.main()

    assert observed["url"] == "https://example.com"
    assert observed["policy"].network_apis is not None
    assert observed["runtime"].fetch_external_scripts is True
    assert not output.exists()

    raw_output = output.with_name("result_raw.json")
    signals_output = output.with_name("result_signals.json")
    raw_document = json.loads(raw_output.read_text(encoding="utf-8"))
    signals_document = json.loads(signals_output.read_text(encoding="utf-8"))

    assert raw_document["layer"] == "L3"
    assert raw_document["raw"]["html"]["forms"] == []
    assert "signals" not in raw_document
    assert signals_document["signals"][0]["id"] == "L3-H-01"
    assert "raw" not in signals_document
    assert raw_document["target"] == signals_document["target"]
    assert raw_document["scan"] == signals_document["scan"]


def test_output_paths_add_json_extension_when_base_has_no_suffix() -> None:
    raw_path, signals_path = main_module._output_paths(Path("results/l3"))

    assert raw_path == Path("results/l3_raw.json")
    assert signals_path == Path("results/l3_signals.json")
