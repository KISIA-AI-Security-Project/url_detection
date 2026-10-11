"""Local AWS handoff and clean-package checks for the approved fast result contract."""
from copy import deepcopy
import json
from pathlib import Path
import re
import zipfile

import pytest

from deployment.build_fast_result_candidate import build, patch_definition, VERSION


EVALUATION = Path(__file__).resolve().parents[3]
DIRECT = EVALUATION / "dns-inactivity-20260916/dual-dns-failure-patch-v2/definition-v5.json"
QUEUED = EVALUATION / "remediation-20260920/integration/release-inputs/definition.json"
ARNS = {f"{role}_arn": f"arn:aws:lambda:ap-northeast-2:998301375101:function:team5-itg-fast-{role}-candidate:1"
        for role in ("context", "judgment", "result")}


def source(path=QUEUED):
    return json.loads(path.read_text(encoding="utf-8"))


def _choice_matches(condition, result):
    if "And" in condition:
        return all(_choice_matches(item, result) for item in condition["And"])
    if "Or" in condition:
        return any(_choice_matches(item, result) for item in condition["Or"])
    name = condition["Variable"].removeprefix("$.final.judgment.")
    if "IsPresent" in condition:
        return (name in result) is condition["IsPresent"]
    return result.get(name) == condition["StringEquals"]


@pytest.mark.parametrize("definition", [DIRECT, QUEUED], ids=["direct", "queued"])
def test_supplied_asl_uses_direct_judgment_and_preserves_collectors(definition):
    original = source(definition)
    before = deepcopy(original)
    candidate = patch_definition(original, **ARNS)
    assert original == before
    states = candidate["States"]
    assert not any(name.startswith("Qwen") for name in states)
    assert "$.qwen" not in json.dumps(candidate)
    assert states["L0L1L23Parallel"] == original["States"]["L0L1L23Parallel"]
    assert states["MarkObserved"] == original["States"]["MarkObserved"]
    assert states["ContextTask"]["Parameters"]["Payload"] == original["States"]["ContextTask"]["Parameters"]["Payload"]
    assert states["ContextTask"]["Parameters"]["FunctionName"] == ARNS["context_arn"]
    assert states["ActivityTask"]["Parameters"]["FunctionName"] == ARNS["context_arn"]
    assert states["JudgmentTask"]["Parameters"]["FunctionName"] == ARNS["judgment_arn"]
    assert states["JudgmentTask"]["Next"] == "JudgmentSucceeded"
    assert states["URLActivityDecision"]["Choices"][-1]["Next"] == "JudgmentTask"


def test_attempt_reset_and_public_reference_updates_are_complete():
    states = patch_definition(source(), **ARNS)["States"]
    allocation = states["AllocAttempt"]["Parameters"]
    assert "ADD #att :one" in allocation["UpdateExpression"]
    assert "result_contract_version = :fast_contract" in allocation["UpdateExpression"]
    assert allocation["ExpressionAttributeValues"][":fast_contract"] == {"S": VERSION}
    removes = allocation["UpdateExpression"].split(" REMOVE ")[1].split(" ADD ")[0]
    assert {"fast_result_key", "context_revision", "result_revision", "final_verdict", "judgment_key"} <= set(removes.split(", "))
    for state_name, path in (("MarkContext", "$.context.ctx"), ("MarkJudged", "$.final.judgment"),
                             ("MarkFastResultFailed", "$.final.judgment")):
        params = states[state_name]["Parameters"]
        assert params["ExpressionAttributeValues"][":fast_key"] == {"S.$": path + ".fast_result_key"}
        assert params["ExpressionAttributeValues"][":fast_context_revision"] == {"S.$": path + ".context_revision"}
    # DynamoDB rejects unused expression attributes; old v2 fields must be removed cleanly.
    for name in ("AllocAttempt", "MarkContext", "MarkJudged", "MarkFastResultFailed", "MarkFailed", "MarkSafetyBlocked"):
        params = states[name]["Parameters"]
        expression = " ".join(v for k, v in params.items() if k.endswith("Expression"))
        used = set(re.findall(r"[#:][A-Za-z0-9_]+", expression))
        declared = set(params.get("ExpressionAttributeNames", {})) | set(params.get("ExpressionAttributeValues", {}))
        assert used == declared, name


@pytest.mark.parametrize("status,target", [("accepted", "MarkJudged"), ("failed", "MarkFastResultFailed"),
                                           ("invalid", "MarkFastResultFailed")])
def test_judgment_status_routes_without_synthetic_verdict(status, target):
    states = patch_definition(source(), **ARNS)["States"]
    returned = {"judgment_status": status, "result_contract_version": VERSION,
                "fast_result_key": "records/job/1/fast/result.json", "context_revision": "context", "result_revision": "result"}
    if status == "accepted":
        returned.update(verdict="UNKNOWN", judgment_key="records/job/1/fast/judgment.json")
    choices = states["JudgmentSucceeded"]["Choices"]
    assert [item["Next"] for item in choices if _choice_matches(item, returned)] == [target]
    failed_params = states["MarkFastResultFailed"]["Parameters"]
    assert "final_verdict" in failed_params["UpdateExpression"].split(" REMOVE ")[1]
    assert not any(value.get("S.$") == "$.final.judgment.verdict" for value in failed_params["ExpressionAttributeValues"].values())
    assert states["MarkFastResultFailed"]["Next"] == "PipelineFailed"
    returned.pop("result_revision")
    assert not any(_choice_matches(item, returned) for item in choices)


def test_old_pass_context_requires_explicit_baseline_instead_of_guessing_routes():
    original = source()
    original["States"]["ContextTask"] = {"Type": "Pass", "Next": "JudgmentTask"}
    with pytest.raises(ValueError, match="explicit_context_state_contract_required"):
        patch_definition(original, **ARNS)


@pytest.mark.parametrize("fast_only", [False, True], ids=["compatible-default", "optional-fast-only"])
def test_built_packages_import_outside_repo_and_result_consumes_only_public_json(tmp_path, fast_only):
    output = tmp_path / "candidate"
    manifest = build(QUEUED, output, **ARNS, model="offline-package-check", base_url="https://example.org/model",
                     secret_id="team5/fast-result/offline-reference", fast_only_result=fast_only)
    assert manifest["aws_actions"] == 0 and manifest["import_verification"] == "passed"
    with zipfile.ZipFile(output / "result.zip") as package:
        assert {"app.py", "fast_public.py", "api_timing.py"} <= set(package.namelist())
        if fast_only:
            assert set(package.namelist()) == {"app.py", "fast_public.py", "api_timing.py"}
        else:
            assert {"evidence_pipeline/aws_judgment_v2.py", "evidence_pipeline/judgment_contract_v2.py",
                    "evidence_pipeline/judgment_view_v2.py", "dns/__init__.py"} <= set(package.namelist())
    with zipfile.ZipFile(output / "context.zip") as package:
        assert {"dns/__init__.py", "evidence_pipeline/aws_runtime.py", "evidence_pipeline/aws_fast_result.py",
                "evidence_pipeline/fast_judgment_prompt.txt"} <= set(package.namelist())
        assert not any("__pycache__" in name for name in package.namelist())
    proof = json.loads((output / "offline-import-verification.json").read_text(encoding="utf-8"))
    assert proof["status"] == "passed" and proof["live_aws_verified"] is False
    assert len(proof["packages"]) == 3
    result = proof["packages"][-1]
    assert result["handler_response"]["judgment_status"] == "accepted"
    assert result["handler_response"]["judgment"]["verdict"] == "UNKNOWN"
    assert result["aws_calls"] == result["model_calls"] == 0
    assert result["result_package_mode"] == ("fast_only" if fast_only else "compatible")
    assert bool(result["legacy_imports"]) is not fast_only
    contract = json.loads((output / "deployment-contract.json").read_text(encoding="utf-8"))
    assert contract["result_api"]["lambda_arn"] == ARNS["result_arn"]
    assert ARNS["result_arn"] not in json.dumps(source()["States"])
    assert contract["lambda"]["judgment"]["environment"]["EVIDENCE_RESULT_CONTRACT"] == VERSION


def test_provider_budget_fits_declared_lambda_and_sfn_deadline(tmp_path):
    with pytest.raises(ValueError, match="invalid_timeout_or_budget_configuration"):
        build(QUEUED, tmp_path / "candidate", **ARNS, model="offline", base_url="https://example.org/model",
              secret_id="team5/fast-result/offline-reference", model_timeout=65, lambda_timeout=60)


def test_explicit_claude_generation_settings_are_packaged_with_matching_deadlines(tmp_path):
    output = tmp_path / "claude55"
    manifest = build(QUEUED, output, **ARNS, model="claude-sonnet-5-5", base_url="https://example.org/model",
                     secret_id="team5/fast-result/offline-reference", omit_temperature=True,
                     output_effort="high", max_tokens=8192, model_timeout=120,
                     lambda_timeout=150, task_timeout=180)
    assert manifest["import_verification"] == "passed" and manifest["aws_actions"] == 0
    contract = json.loads((output / "deployment-contract.json").read_text(encoding="utf-8"))
    judgment = contract["lambda"]["judgment"]
    assert judgment["environment"]["ANTHROPIC_OMIT_TEMPERATURE"] == "1"
    assert judgment["environment"]["ANTHROPIC_OUTPUT_EFFORT"] == "high"
    assert judgment["environment"]["JUDGMENT_MODEL"] == "claude-sonnet-5-5"
    assert judgment["environment"]["JUDGMENT_MAX_TOKENS"] == "8192"
    assert judgment["environment"]["LLM_TIMEOUT_SECONDS"] == "120"
    assert judgment["timeout_seconds"] == 150
    definition = json.loads((output / "definition.json").read_text(encoding="utf-8"))
    assert definition["States"]["JudgmentTask"]["TimeoutSeconds"] == 180
