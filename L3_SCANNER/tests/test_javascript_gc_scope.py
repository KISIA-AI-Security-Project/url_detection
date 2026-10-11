from types import SimpleNamespace

import pytest

import L3_SCANNER.l3_scanner as module
from L3_SCANNER.models.input import HTMLInput, L3Input, ScriptInput
from L3_SCANNER.policies.detection import DetectionPolicy
from L3_SCANNER.policies.runtime import RuntimeConfig


@pytest.mark.parametrize("enabled", [True, False])
@pytest.mark.parametrize("parse_fails", [True, False])
def test_gc_scope_preserves_result_exception_and_initial_state(monkeypatch, enabled, parse_fails):
    events, state = [], {"enabled": enabled}
    expected, error = {"original": "native result"}, ValueError("original parse failure")

    def change(value):
        state["enabled"] = value
        events.append("enable" if value else "disable")

    def parse(*args):
        events.append("parse")
        assert not state["enabled"]
        if parse_fails:
            raise error
        return expected

    monkeypatch.setattr(module, "gc", SimpleNamespace(isenabled=lambda: state["enabled"],
        disable=lambda: change(False), enable=lambda: change(True), collect=lambda: events.append("collect")))
    monkeypatch.setattr(module, "parse_javascript", parse)
    source = L3Input("https://example.com", "https://example.com", HTMLInput(""),
                     scripts=[ScriptInput("inline", "inline", source="const x = 1;")])
    if parse_fails:
        with pytest.raises(ValueError) as caught:
            module._parse_javascript_with_deferred_gc(source, {}, DetectionPolicy(), RuntimeConfig())
        assert caught.value is error
    else:
        assert module._parse_javascript_with_deferred_gc(source, {}, DetectionPolicy(), RuntimeConfig()) is expected
    assert state["enabled"] is enabled
    assert events == (["disable", "parse", "collect", "enable"] if enabled else ["parse"])


def test_gc_is_restored_even_if_cleanup_raises(monkeypatch):
    events = []

    def collect():
        events.append("collect")
        raise RuntimeError("cleanup failed")

    monkeypatch.setattr(module, "gc", SimpleNamespace(isenabled=lambda: True,
        disable=lambda: events.append("disable"), enable=lambda: events.append("enable"), collect=collect))
    monkeypatch.setattr(module, "parse_javascript", lambda *args: {})
    source = L3Input("https://example.com", "https://example.com", HTMLInput(""),
                     scripts=[ScriptInput("inline", "inline", source="const x = 1;")])
    with pytest.raises(RuntimeError, match="cleanup failed"):
        module._parse_javascript_with_deferred_gc(source, {}, DetectionPolicy(), RuntimeConfig())
    assert events == ["disable", "collect", "enable"]
