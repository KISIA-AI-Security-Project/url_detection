from copy import deepcopy
from threading import Barrier, Lock

import L3_SCANNER.l3_scanner as module
from L3_SCANNER.models.input import HTMLInput, L3Input, ScriptInput
from L3_SCANNER.policies.runtime import RuntimeConfig


def test_concurrent_fetch_preserves_selection_order_duplicates_and_limits(monkeypatch):
    scripts = [ScriptInput(str(i), "external", source_url=f"https://cdn.example/{i}.js")
               for i in range(6)]
    scripts.insert(2, ScriptInput("duplicate", "external", source_url="https://cdn.example/0.js#other"))
    scripts.extend([
        ScriptInput("inline", "inline", source="const inlineValue = 1;"),
        ScriptInput("provided", "external", source_url="https://cdn.example/provided.js", source="const supplied = 2;"),
        ScriptInput("data", "external", source_url="https://cdn.example/data", media_type="application/json"),
    ])
    supplied = L3Input("https://example.com", "https://example.com", HTMLInput(""), scripts=scripts)
    original = deepcopy(supplied)
    barrier, lock, calls = Barrier(5, timeout=5), Lock(), []

    def collect(script, runtime):
        with lock:
            calls.append(script.script_id)
        barrier.wait()  # Fails if the five independent requests are serialized.
        script.source = f"const s{script.script_id} = 1;"
        script.source_url += "?redirected"
        script.size = len(script.source)
        script.sha256 = "preserved-" + script.script_id
        script.collection_errors = [{"code": "observed", "details": {"script": script.script_id}}]
        script.response = {"status_code": 200, "headers": {"x-script": script.script_id}}

    monkeypatch.setattr(module, "collect_external_script", collect)
    out = module._prepare_scripts(supplied, {}, RuntimeConfig(fetch_external_scripts=True, max_external_scripts=5), fetch_external_sources=True)
    assert supplied == original
    assert sorted(calls) == ["0", "1", "2", "3", "4"]
    assert [s.script_id for s in out] == [s.script_id for s in scripts]
    first, duplicate = out[0], out[2]
    for field in ("source", "sha256", "size", "truncated", "collection_errors", "response"):
        assert getattr(first, field) == getattr(duplicate, field)
    assert duplicate.source_url == "https://cdn.example/0.js#other"
    duplicate.collection_errors[0]["details"]["script"] = "changed"
    duplicate.response["headers"]["x-script"] = "changed"
    assert first.collection_errors[0]["details"]["script"] == "0"
    assert first.response["headers"]["x-script"] == "0"
    limited = next(s for s in out if s.script_id == "5")
    assert limited.source is None
    assert limited.collection_errors[0]["code"] == "external_script_limit_exceeded"
    assert out[-3:] == original.scripts[-3:]


def test_failed_fetch_is_shared_with_duplicate_without_retry(monkeypatch):
    scripts = [ScriptInput("a", "external", source_url="https://cdn.example/missing.js"),
               ScriptInput("b", "external", source_url="https://cdn.example/missing.js#same")]
    supplied = L3Input("https://example.com", "https://example.com", HTMLInput(""), scripts=scripts)
    calls = []

    def collect(script, runtime):
        calls.append(script.script_id)
        script.collection_errors.append({"code": "script_request_timeout"})
        return script

    monkeypatch.setattr(module, "collect_external_script", collect)
    result = module._prepare_scripts(supplied, {}, RuntimeConfig(fetch_external_scripts=True, max_external_scripts=1), fetch_external_sources=True)
    assert calls == ["a"]
    assert result[0].source is result[1].source is None
    assert result[0].collection_errors == result[1].collection_errors == [{"code": "script_request_timeout"}]


def test_zero_budget_does_not_start_collection(monkeypatch):
    def unexpected(*args):
        raise AssertionError("collection must not start")

    monkeypatch.setattr(module, "collect_external_script", unexpected)
    supplied = L3Input("https://example.com", "https://example.com", HTMLInput(""), scripts=[
        ScriptInput("a", "external", source_url="https://cdn.example/app.js")])
    out = module._prepare_scripts(supplied, {}, RuntimeConfig(fetch_external_scripts=True, max_external_scripts=0), fetch_external_sources=True)
    assert out[0].collection_errors[0]["code"] == "external_script_limit_exceeded"
