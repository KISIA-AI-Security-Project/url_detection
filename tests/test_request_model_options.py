"""Offline request-to-provider proof; fixture choices do not claim live access."""
from copy import deepcopy
import io
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import zipfile

import pytest

from evidence_pipeline import aws_fast_result, aws_runtime
from evidence_pipeline.bedrock_gateway import BedrockAnthropicGateway
from evidence_pipeline.model_choices import (ModelChoiceError, bind_model_selection,
    model_configuration, public_model_choices, select_model, validate_selection)
from web_service.api import ApiError, WebApi
from test_web_service import MemoryLedger, OWNER, SCAN, fast
from test_gate_prepared_route import gate  # offline AWS doubles
from test_fast_result_contract import MemoryStore, build_persisted, response_for
from test_fast_result_deployment import ARNS, QUEUED, source


# These two IDs are test inputs, not an operator-declared production catalog.
CATALOG = {"default_model_choice": "sonnet", "models": {
    "sonnet": {"label": "Claude Sonnet (offline fixture)", "provider": "bedrock",
               "model": "global.anthropic.claude-sonnet-5-5", "output_effort": "high",
               "efforts": ["low", "medium", "high", "xhigh", "max"]},
    "opus": {"label": "Claude Opus (offline fixture)", "provider": "bedrock",
             "model": "global.anthropic.claude-opus-5-5", "output_effort": "medium",
             "efforts": ["low", "medium", "high", "xhigh", "max"]}}}


@pytest.fixture
def choices(monkeypatch):
    monkeypatch.setenv("FAST_MODEL_CHOICES_JSON", json.dumps(CATALOG))
    monkeypatch.setenv("FAST_MODEL_SELECTION_ENABLED", "1")
    return deepcopy(CATALOG)


def authenticated(path):
    return {"rawPath": path, "requestContext": {"http": {"method": "GET"},
        "authorizer": {"jwt": {"claims": {"sub": OWNER, "token_use": "access"}}}}}


@pytest.fixture
def api():
    ledger, calls, deep_calls = MemoryLedger(), [], []
    result = fast()
    def invoke(role, event):
        calls.append((role, deepcopy(event)))
        if role == "result":
            return 200, deepcopy(result)
        body = json.loads(event["body"])
        receipt = {"scanId": SCAN, "pollUrl": "/analyses/" + SCAN, "status": "PENDING", "rescan": False}
        if "model_selection" in body:
            receipt.update(model_choice=body["model_choice"], model_profile_sha256=body["model_selection"]["profile_sha256"],
                           reasoning_effort=body["model_selection"]["profile"]["output_effort"])
        return 202, receipt
    def deep_start(owner, value):
        deep_calls.append(deepcopy(value))
        ledger.put_new(owner, "RUN", "run-1", {"input": deepcopy(value)})
        return 202, {"run_id": "run-1"}
    return WebApi(ledger, invoke, lambda event: None, deep_start=deep_start), calls, deep_calls


def submission(**fields):
    return {"url": "https://example.com/", "request_id": "1" * 32, **fields}


def test_catalog_is_authenticated_and_exposes_only_configured_labels(api, choices):
    app, _, _ = api
    reply = app.handle(authenticated("/api/analysis-models"))
    public = json.loads(reply["body"])
    assert public == {"default_model_choice": "sonnet", "models": [
        {"id": key, "label": value["label"], "efforts": value["efforts"],
         "default_effort": value["output_effort"]} for key, value in CATALOG["models"].items()]}
    assert all(set(value) == {"id", "label", "efforts", "default_effort"} for value in public["models"])
    with pytest.raises(ApiError) as caught:
        app.handle({"rawPath": "/api/analysis-models", "requestContext": {"http": {"method": "GET"}}})
    assert caught.value.status == 401


def test_configured_environment_default_compatibility(monkeypatch):
    env = {"JUDGMENT_MODEL": "claude-sonnet-5-5", "ANTHROPIC_OMIT_TEMPERATURE": "1",
           "ANTHROPIC_OUTPUT_EFFORT": "high", "LLM_TIMEOUT_SECONDS": "45"}
    assert public_model_choices(env) == {"default_model_choice": "configured",
        "models": [{"id": "configured", "label": "claude-sonnet-5-5", "efforts": ["high"], "default_effort": "high"}]}
    assert select_model("configured", env)["profile"]["timeout"] == 45
    with pytest.raises(ModelChoiceError, match="model_choices_unavailable"):
        public_model_choices({})


@pytest.mark.parametrize("bad", [None, 1, True, "", "other", "https://remote/model", " opus"])
def test_invalid_selection_has_no_gate_or_ledger_write(api, choices, bad):
    app, calls, _ = api
    with pytest.raises(ApiError):
        app.submit(OWNER, submission(model_choice=bad))
    assert calls == [] and app.ledger.rows == {}


def test_choice_is_in_request_identity_and_gate_snapshot(api, choices):
    app, calls, _ = api
    response = app.submit(OWNER, submission(model_choice="opus"))
    assert app.submit(OWNER, submission(model_choice="opus")) == response
    assert len(calls) == 1
    gate_body = json.loads(calls[0][1]["body"])
    assert gate_body == {"url": "https://example.com/", "model_choice": "opus", "reasoning_effort": "medium",
                         "model_selection": select_model("opus")}
    saved = app.ledger.get(OWNER, "REQUEST", "1" * 32)
    assert saved["model_selection"] == gate_body["model_selection"]
    for changed in ({"model_choice": "sonnet"}, {}):
        with pytest.raises(ApiError) as caught:
            app.submit(OWNER, submission(**changed))
        assert caught.value.code == "request_changed"


def test_old_gate_receipt_does_not_claim_requested_model_was_applied(api, choices):
    app, _, _ = api
    app.invoke = lambda role, event: (202, {"scanId": SCAN, "pollUrl": "/analyses/" + SCAN})
    with pytest.raises(ApiError) as caught:
        app.submit(OWNER, submission(model_choice="opus"))
    assert caught.value.code == "model_selection_unconfirmed"


def test_gate_freezes_selection_into_execution_without_exposing_profile(gate, choices):
    module, calls, _, _ = gate
    result = module.handler({"body": json.dumps({"url": "https://example.com/", "model_choice": "opus"})}, None)
    assert result["statusCode"] == 202
    receipt = json.loads(result["body"])
    assert receipt["model_choice"] == "opus" and "model_selection" not in receipt
    execution = json.loads(next(kwargs["input"] for name, kwargs in calls if name == "start"))
    assert execution["model_selection"] == select_model("opus")


@pytest.mark.parametrize("mode", ["disabled", "unknown", "changed", "legacy_route"])
def test_gate_rejects_unavailable_or_changed_selection_before_start(gate, choices, monkeypatch, mode):
    module, calls, _, _ = gate
    body = {"url": "https://example.com/", "model_choice": "opus"}
    if mode == "disabled":
        monkeypatch.delenv("FAST_MODEL_SELECTION_ENABLED")
    elif mode == "unknown":
        body["model_choice"] = "not-configured"
    elif mode == "changed":
        body["model_selection"] = select_model("sonnet")
    else:
        body["scanId"] = "1" * 32
    result = module.handler({"body": json.dumps(body)}, None)
    assert result["statusCode"] in (400, 409, 503)
    assert not any(name in ("put", "start") for name, _ in calls)


@pytest.mark.parametrize("change", ["hash", "provider", "not_claude", "field", "effort", "timeout", "default"])
def test_invalid_server_config_and_snapshot_are_rejected(choices, change):
    snapshot = select_model("opus")
    if change == "hash":
        snapshot["profile"]["model"] = "global.anthropic.claude-sonnet-5-5"
        with pytest.raises(ModelChoiceError, match="hash"):
            validate_selection(snapshot)
        return
    candidate = deepcopy(CATALOG)
    profile = candidate["models"]["opus"]
    if change == "provider": profile["provider"] = "openai"
    if change == "not_claude": profile["model"] = "gpt-6-astra"
    if change == "field": profile["endpoint"] = "https://example.com/"
    if change == "effort": profile["output_effort"] = "ultra"
    if change == "timeout": profile["timeout"] = True
    if change == "default": candidate["default_model_choice"] = "missing"
    with pytest.raises(ModelChoiceError):
        model_configuration({"FAST_MODEL_CHOICES_JSON": json.dumps(candidate)})


def test_model_snapshot_change_does_not_fall_back(choices, monkeypatch):
    selected = select_model("opus")
    changed = deepcopy(CATALOG)
    changed["models"]["opus"]["max_tokens"] = 4096
    monkeypatch.setenv("FAST_MODEL_CHOICES_JSON", json.dumps(changed))
    with pytest.raises(ModelChoiceError, match="model_configuration_changed"):
        validate_selection(selected)


@pytest.mark.parametrize("effort", ["low", "medium", "high", "xhigh", "max"])
def test_effort_is_resolved_into_existing_seven_field_profile(choices, effort):
    selected = select_model("opus", reasoning_effort=effort)
    assert selected["profile"]["output_effort"] == effort
    assert set(selected["profile"]) == {"label", "provider", "model", "timeout", "max_tokens", "output_effort", "omit_temperature"}
    assert validate_selection(selected) == selected
    assert validate_selection(selected, current=False) == selected


@pytest.mark.parametrize("bad", [None, "", "HIGH", " ultra", "ultra", 1, True, [], {}])
def test_invalid_effort_has_no_api_or_gate_write(api, gate, choices, bad):
    app, api_calls, _ = api
    with pytest.raises(ApiError) as caught:
        app.submit(OWNER, submission(model_choice="opus", reasoning_effort=bad))
    assert caught.value.code == "invalid_reasoning_effort"
    assert not api_calls and not app.ledger.rows
    module, gate_calls, _, _ = gate
    response = module.handler({"body": json.dumps({"url": "https://example.com/", "model_choice": "opus", "reasoning_effort": bad})}, None)
    assert response["statusCode"] == 400
    assert json.loads(response["body"])["error"] == "invalid_reasoning_effort"
    assert not gate_calls


def test_effort_requires_model_and_model_specific_permission(api, gate, choices, monkeypatch):
    app, calls, _ = api
    module, gate_calls, _, _ = gate
    for fields, error in [({"reasoning_effort": "low"}, "model_choice_required"),
                          ({"model_choice": "opus", "reasoning_effort": "max"}, "unsupported_reasoning_effort")]:
        catalog = deepcopy(CATALOG)
        catalog["models"]["opus"]["efforts"] = ["medium"]
        monkeypatch.setenv("FAST_MODEL_CHOICES_JSON", json.dumps(catalog))
        with pytest.raises(ApiError) as caught:
            app.submit(OWNER, submission(**fields))
        assert caught.value.code == error
        reply = module.handler({"body": json.dumps({"url": "https://example.com/", **fields})}, None)
        assert reply["statusCode"] == 400 and json.loads(reply["body"])["error"] == error
    assert not calls and not gate_calls and not app.ledger.rows


@pytest.mark.parametrize("efforts", [None, "high", ["high", "high"], ["ultra"], [None], [1], [], ["low"]])
def test_invalid_capability_configuration_fails(choices, efforts):
    config = deepcopy(CATALOG)
    config["models"]["sonnet"]["efforts"] = efforts
    with pytest.raises(ModelChoiceError, match="invalid_model_configuration"):
        model_configuration({"FAST_MODEL_CHOICES_JSON": json.dumps(config)})


def test_capabilities_do_not_change_existing_profile_hash(choices, monkeypatch):
    selected = select_model("sonnet")
    old = deepcopy(CATALOG)
    for profile in old["models"].values():
        profile.pop("efforts")
    monkeypatch.setenv("FAST_MODEL_CHOICES_JSON", json.dumps(old))
    assert select_model("sonnet") == selected
    assert validate_selection(selected) == selected
    assert public_model_choices()["models"][0]["efforts"] == ["high"]
    old["models"]["sonnet"]["output_effort"] = None
    env = {"FAST_MODEL_CHOICES_JSON": json.dumps(old)}
    assert public_model_choices(env)["models"][0]["efforts"] == []
    assert public_model_choices(env)["models"][0]["default_effort"] is None
    assert select_model("sonnet", env)["profile"]["output_effort"] is None
    old["models"]["sonnet"]["efforts"] = ["high"]
    with pytest.raises(ModelChoiceError):
        model_configuration({"FAST_MODEL_CHOICES_JSON": json.dumps(old)})


def test_effective_effort_identity_and_legacy_cached_retry(api, choices, monkeypatch):
    app, calls, _ = api
    first = app.submit(OWNER, submission(model_choice="sonnet"))
    assert first[1]["reasoning_effort"] == "high"
    assert app.submit(OWNER, submission(model_choice="sonnet", reasoning_effort="high")) == first
    legacy = app.ledger.get(OWNER, "REQUEST", "1" * 32)
    legacy["input"].pop("reasoning_effort")
    legacy["response"].pop("reasoning_effort")
    app.ledger.replace(OWNER, "REQUEST", "1" * 32, legacy)
    assert app.submit(OWNER, submission(model_choice="sonnet")) == first
    assert app.submit(OWNER, submission(model_choice="sonnet", reasoning_effort="high")) == first
    with pytest.raises(ApiError) as caught:
        app.submit(OWNER, submission(model_choice="sonnet", reasoning_effort="low"))
    assert caught.value.code == "request_changed"
    changed = deepcopy(CATALOG)
    changed["models"]["sonnet"]["output_effort"] = "medium"
    monkeypatch.setenv("FAST_MODEL_CHOICES_JSON", json.dumps(changed))
    # Omission means the current default. After a default change it is a different
    # request; an explicit old effort can still retrieve its frozen acceptance.
    with pytest.raises(ApiError) as caught:
        app.submit(OWNER, submission(model_choice="sonnet"))
    assert caught.value.code == "request_changed"
    assert app.submit(OWNER, submission(model_choice="sonnet", reasoning_effort="high")) == first
    assert len(calls) == 1


def test_default_change_preserves_permitted_frozen_effort_but_removal_rejects(choices, monkeypatch):
    selected = select_model("opus", reasoning_effort="max")
    changed = deepcopy(CATALOG)
    changed["models"]["opus"]["output_effort"] = "high"
    monkeypatch.setenv("FAST_MODEL_CHOICES_JSON", json.dumps(changed))
    assert validate_selection(selected) == selected
    changed["models"]["opus"]["efforts"].remove("max")
    monkeypatch.setenv("FAST_MODEL_CHOICES_JSON", json.dumps(changed))
    with pytest.raises(ModelChoiceError, match="model_configuration_changed"):
        validate_selection(selected)
    assert validate_selection(selected, current=False) == selected


def test_selection_is_bound_before_same_attempt_result_reuse(choices):
    store = MemoryStore()
    event = {"model_selection": select_model("opus")}
    bind_model_selection(event, store, "job", "1")
    bind_model_selection(deepcopy(event), store, "job", "1")
    store.put("records/job/1/fast/result.json", {"fixture": True})
    for changed in ({}, {"model_selection": select_model("sonnet")},
                    {"model_selection": select_model("opus", reasoning_effort="low")}):
        with pytest.raises(ModelChoiceError, match="attempt_mismatch"):
            bind_model_selection(changed, store, "job", "1")
    old = MemoryStore()
    old.put("records/job/1/fast/request-claim.json", {"context_revision": "old"})
    bind_model_selection({}, old, "job", "1")  # old legacy receipt remains readable
    with pytest.raises(ModelChoiceError, match="already_started"):
        bind_model_selection(event, old, "job", "1")


@pytest.mark.parametrize("effort", ["low", "medium", "high", "xhigh", "max"])
def test_runtime_uses_selected_bedrock_model_and_preserves_actual_body(api, gate, choices, monkeypatch, effort):
    app, _, _ = api
    module, gate_calls, _, _ = gate
    def invoke_gate(role, request):
        assert role == "gate"
        reply = module.handler(request, None)
        return reply["statusCode"], json.loads(reply["body"])
    app.invoke = invoke_gate
    accepted = app.submit(OWNER, submission(model_choice="opus", reasoning_effort=effort))
    assert accepted[1]["reasoning_effort"] == effort
    execution = json.loads(next(kwargs["input"] for name, kwargs in gate_calls if name == "start"))
    event, store, output, _ = build_persisted("login")
    event.update(model_selection=execution["model_selection"], context_key=output["final_key"],
                 context_sha256=output["context_sha256"])
    monkeypatch.setattr(aws_runtime, "Store", lambda *args, **kwargs: store)
    monkeypatch.setattr("evidence_pipeline.aws_clients.get_s3_client", lambda: object())
    for key, value in {"EVIDENCE_RESULT_CONTRACT": "fast-result-1", "JUDGMENT_PROVIDER": "bedrock",
                       "JUDGMENT_MODEL": "global.anthropic.claude-sonnet-5-5", "AWS_REGION": "ap-northeast-2"}.items():
        monkeypatch.setenv(key, value)
    calls = []
    def invoke(**kwargs):
        calls.append(kwargs)
        return {"body": io.BytesIO(json.dumps({"stop_reason": "end_turn", "content": [
            {"type": "text", "text": json.dumps(response_for("login"))}]}).encode())}
    monkeypatch.setattr("evidence_pipeline.aws_clients.get_bedrock_client", lambda **kwargs: SimpleNamespace(invoke_model=invoke))
    result = aws_runtime._handle(event, "judgment")
    assert result["judgment_status"] == "accepted" and len(calls) == 1
    assert calls[0]["modelId"] == CATALOG["models"]["opus"]["model"]
    sent = json.loads(calls[0]["body"])
    paths = aws_fast_result.keys(event["job_id"], 1)
    assert sent == store.get(paths["request"])
    assert sent["output_config"] == {"effort": effort}
    assert sent["messages"][0]["content"] == store.get(paths["context"])["model_body"]
    assert aws_runtime._handle(deepcopy(event), "judgment") == result
    assert len(calls) == 1
    event["model_selection"] = select_model("sonnet")
    with pytest.raises(ModelChoiceError, match="attempt_mismatch"):
        aws_runtime._handle(event, "judgment")
    assert len(calls) == 1


def test_anthropic_selection_reaches_actual_messages_request(choices, monkeypatch):
    configured = deepcopy(CATALOG)
    for profile in configured["models"].values():
        profile.update(provider="anthropic", model=profile["model"].removeprefix("global.anthropic."),
                       omit_temperature=True)
    monkeypatch.setenv("FAST_MODEL_CHOICES_JSON", json.dumps(configured))
    event, store, output, _ = build_persisted("login")
    event.update(model_selection=select_model("opus", reasoning_effort="max"), context_key=output["final_key"],
                 context_sha256=output["context_sha256"])
    monkeypatch.setattr(aws_runtime, "Store", lambda *args, **kwargs: store)
    monkeypatch.setattr("evidence_pipeline.aws_clients.get_s3_client", lambda: object())
    monkeypatch.setitem(sys.modules, "boto3", SimpleNamespace(client=lambda service:
        SimpleNamespace(get_secret_value=lambda **kwargs: {"SecretString": "offline-test-key"})
        if service == "secretsmanager" else pytest.fail("unexpected AWS client")))
    for key, value in {"EVIDENCE_RESULT_CONTRACT": "fast-result-1", "JUDGMENT_PROVIDER": "anthropic",
                       "JUDGMENT_MODEL": "claude-sonnet-5-5", "ANTHROPIC_BASE_URL": "https://offline.invalid",
                       "LLM_SECRET_ID": "offline-secret-ref"}.items():
        monkeypatch.setenv(key, value)
    calls = []
    def open_request(request, **kwargs):
        calls.append(json.loads(request.data))
        return io.BytesIO(json.dumps({"stop_reason": "end_turn", "content": [
            {"type": "text", "text": json.dumps(response_for("login"))}]}).encode())
    monkeypatch.setattr("urllib.request.build_opener", lambda *args: SimpleNamespace(open=open_request))
    result = aws_runtime._handle(event, "judgment")
    assert result["judgment_status"] == "accepted" and len(calls) == 1
    assert calls[0]["model"] == "claude-opus-5-5"
    assert calls[0]["output_config"] == {"effort": "max"} and "temperature" not in calls[0]
    assert store.get(aws_fast_result.keys(event["job_id"], 1)["request"]) == calls[0]


def test_prepared_callback_cannot_erase_selected_model():
    from deployment.build_fast_result_candidate import patch_model_selection_definition
    path = Path(__file__).resolve().parents[3] / "remediation-20261006/fast-verdict-review/five-verdict-1/release5/live-1/active-sfn.json"
    original = json.loads(json.loads(path.read_text(encoding="utf-8"))["definition"])
    patched = patch_model_selection_definition(original)
    # The prepared callback replaces state; the selection remains in the
    # original execution input and is reattached only when Judgment is reached.
    assert patched["States"]["ApplyPreparedState"] == original["States"]["ApplyPreparedState"]
    assert patched["States"]["ApplyLambdaFallbackState"] == original["States"]["ApplyLambdaFallbackState"]
    assert patched["States"]["PreparedWorkerTask"] == original["States"]["PreparedWorkerTask"]
    assert patched["States"]["UseModelSelection"]["Parameters"]["selected.$"] == "$$.Execution.Input.model_selection"
    changed = {name for name in original["States"] if original["States"][name] != patched["States"][name]}
    assert changed == {"JudgmentTask", "URLActivityDecision"}
    assert patched["States"]["ContextTask"] == original["States"]["ContextTask"]


@pytest.mark.parametrize("value,expected", [("  로그인 후 전송 대상을 확인해 주세요.\n", "로그인 후 전송 대상을 확인해 주세요."),
                                           (" \t\n", None), ("😀" * 2000, "😀" * 2000)],
                         ids=["trimmed", "blank", "unicode-boundary"])
def test_deep_optional_text_is_separate_from_fast_revision(api, value, expected):
    app, _, deep_calls = api
    app.submit(OWNER, submission())
    identity = {key: fast()[key] for key in ("job_id", "attempt", "context_revision", "result_revision")}
    request = {**identity, "request_text": value}
    before = deepcopy(request)
    app.start_deep(OWNER, SCAN, request)
    assert request == before
    assert deep_calls == [{**identity, **({"request_text": expected} if expected else {})}]


@pytest.mark.parametrize("value", [None, False, 2, {}, [], "가" * 2001, "😀" * 2001, "\ud800"],
                         ids=["null", "bool", "number", "object", "list", "too-long", "utf8-too-long", "invalid-unicode"])
def test_deep_invalid_text_never_reaches_l4(api, value):
    app, _, deep_calls = api
    app.submit(OWNER, submission())
    identity = {key: fast()[key] for key in ("job_id", "attempt", "context_revision", "result_revision")}
    with pytest.raises(ApiError) as caught:
        app.start_deep(OWNER, SCAN, {**identity, "request_text": value})
    assert caught.value.code == "invalid_request_text" and deep_calls == []


def test_deep_unicode_boundary_survives_actual_lambda_wire(monkeypatch):
    from web_service import api as web_api
    project = Path(__file__).resolve().parents[4]
    monkeypatch.syspath_prepend(str(project / "l4-orchestrator/src"))
    monkeypatch.setitem(sys.modules, "boto3", SimpleNamespace())
    monkeypatch.setitem(sys.modules, "botocore.exceptions", SimpleNamespace(ClientError=type("ClientError", (Exception,), {})))
    monkeypatch.setitem(sys.modules, "botocore.config", SimpleNamespace(Config=lambda **kwargs: object()))
    from l4_orchestrator.aws_start import parse_input

    ledger, sent = MemoryLedger(), []
    ledger.put_new(OWNER, "JOB", SCAN, {"scan_id": SCAN, "url": "https://example.com/"})
    result = fast()
    identity = {key: result[key] for key in ("job_id", "attempt", "context_revision", "result_revision")}
    request = {**identity, "request_text": "😀" * 2000}

    def invoke(**kwargs):
        wire = json.loads(kwargs["Payload"])
        if kwargs["FunctionName"] == "result":
            status, value = 200, result
        else:
            assert kwargs["FunctionName"] == "deep"
            sent.append(wire)
            assert len(wire["body"].encode("utf-8")) < 16384
            assert parse_input(wire) == request
            ledger.put_new(OWNER, "RUN", "wire-run", {"input": request})
            status, value = 202, {"run_id": "wire-run"}
        return {"Payload": io.BytesIO(json.dumps({"statusCode": status, "body": json.dumps(value)}).encode())}

    monkeypatch.setitem(sys.modules, "boto3", SimpleNamespace(
        client=lambda service, **kwargs: SimpleNamespace(invoke=invoke) if service == "lambda" else object(),
        resource=lambda service: SimpleNamespace(Table=lambda name: object())))
    monkeypatch.setattr(web_api, "Ledger", lambda table: ledger)
    for key, value in {"WEB_JOBS_TABLE": "offline", "FAST_GATE_ARN": "gate",
                       "FAST_RESULT_ARN": "result", "DEEP_START_ARN": "deep"}.items():
        monkeypatch.setenv(key, value)
    app = web_api.runtime()
    event = authenticated("/api/analyses/" + SCAN + "/deep")
    event["requestContext"]["http"]["method"] = "POST"
    event["body"] = json.dumps(request, ensure_ascii=False)
    response = app.handle(event)
    assert response["statusCode"] == 202 and len(sent) == 1


def test_deployment_contains_catalog_route_modules_and_optional_sfn_pass(tmp_path):
    from deployment.build_fast_result_candidate import build, patch_definition
    from deployment.deploy_web_service import code_zip, openapi
    document = openapi("pool", "api", "stream")
    assert document["paths"]["/api/analysis-models"]["get"]["security"]
    with zipfile.ZipFile(io.BytesIO(code_zip())) as archive:
        assert {"evidence_pipeline/__init__.py", "evidence_pipeline/model_choices.py",
                "evidence_pipeline/request_options.py"} <= set(archive.namelist())
    candidate = patch_definition(source(), **ARNS, model_choices_enabled=True)
    assert candidate["StartAt"] == source()["StartAt"]
    states = candidate["States"]
    assert states["DefaultModelSelection"]["Result"] == {"selected": {}}
    assert states["UseModelSelection"]["Parameters"] == {"selected.$": "$$.Execution.Input.model_selection"}
    assert states["JudgmentTask"]["Parameters"]["Payload"]["model_selection.$"] == "$.model_options.selected"
    assert states["L0L1L23Parallel"] == source()["States"]["L0L1L23Parallel"]
    output = tmp_path / "candidate"
    manifest = build(QUEUED, output, **ARNS, model=CATALOG["models"]["sonnet"]["model"],
                     provider="bedrock", lambda_timeout=150, task_timeout=180, model_choices=CATALOG)
    contract = json.loads((output / "deployment-contract.json").read_text(encoding="utf-8"))
    assert manifest["aws_actions"] == 0 and manifest["import_verification"] == "passed"
    choice_env = contract["model_selection"]["server_environment"]
    assert choice_env == contract["model_selection"]["api_environment_additions"]
    assert contract["lambda"]["judgment"]["environment"]["FAST_MODEL_CHOICES_JSON"] == choice_env["FAST_MODEL_CHOICES_JSON"]
    with zipfile.ZipFile(output / "gate.zip") as archive:
        assert "evidence_pipeline/model_choices.py" in archive.namelist()
        extracted = tmp_path / "gate"
        archive.extractall(extracted)
    probe = """import os, sys, types
sys.path.insert(0, sys.argv[1])
sys.modules['boto3'] = types.SimpleNamespace(client=lambda service: object())
os.environ.update(JOBS_TABLE='offline', STATE_MACHINE_ARN='offline')
import app
assert app.select_model
print('isolated-gate-import-ok')
"""
    run = subprocess.run([sys.executable, "-I", "-S", "-B", "-X", "utf8", "-c", probe, str(extracted)],
                         cwd=extracted, capture_output=True, text=True, encoding="utf-8")
    assert run.returncode == 0, run.stderr


def test_deployment_rejects_choices_that_exceed_runtime_or_change_transport(tmp_path):
    from deployment.build_fast_result_candidate import build
    for change in ("deadline", "provider"):
        catalog = deepcopy(CATALOG)
        catalog["models"]["opus"]["timeout" if change == "deadline" else "provider"] = 200 if change == "deadline" else "anthropic"
        with pytest.raises(ValueError, match="provider_or_deadline"):
            build(QUEUED, tmp_path / change, **ARNS, model=CATALOG["models"]["sonnet"]["model"],
                  provider="bedrock", lambda_timeout=150, task_timeout=180, model_choices=catalog)
