from __future__ import annotations

import pytest

from L3_SCANNER.models.input import L3Input
from L3_SCANNER.models.signal import signal_result
from L3_SCANNER.utils.url import etld1, resolve_http_url


def test_input_mapping_preserves_missing_external_script_source() -> None:
    value = L3Input.from_mapping(
        {
            "original_url": "https://login.example.co.uk",
            "html": {"content": "<html></html>"},
            "scripts": [
                {
                    "script_id": "script-1",
                    "type": "external",
                    "source_url": "https://cdn.example/app.js",
                }
            ],
        }
    )
    assert value.document_url == value.original_url
    assert value.scripts[0].source is None


def test_etld1_is_psl_aware_and_rejects_ip_literals() -> None:
    assert etld1("https://a.b.example.co.uk/path") == "example.co.uk"
    assert etld1("https://127.0.0.1/") is None


def test_url_resolution_only_returns_http_destinations() -> None:
    assert (
        resolve_http_url("../submit", "https://example.com/a/")
        == "https://example.com/submit"
    )
    assert resolve_http_url("javascript:alert(1)", "https://example.com/") is None


def test_non_evaluated_signal_cannot_claim_negative() -> None:
    with pytest.raises(ValueError):
        signal_result(
            "L3-H-01",
            "html",
            "credential_form",
            status="error",
            detected=False,
        )
