"""The combined call must retain the downstream result and safety contracts."""
from copy import deepcopy

import pytest

from deployment.build_combined_context_candidate import patch_definition
from deployment.build_fast_result_candidate import patch_definition as fast_definition
from test_fast_result_deployment import DIRECT, QUEUED, source, ARNS


@pytest.mark.parametrize("path", [DIRECT, QUEUED])
def test_combined_call_preserves_all_other_safety_and_result_states(path):
    original = fast_definition(source(path), **ARNS)
    before = deepcopy(original)
    value = patch_definition(original, context_arn=ARNS["context_arn"])
    assert original == before
    a, b = original["States"], value["States"]
    assert a.keys() == b.keys()
    assert {k: v for k, v in a.items() if k not in ("ActivityTask", "ContextTask")} == {
        k: v for k, v in b.items() if k not in ("ActivityTask", "ContextTask")
    }
    assert b["ActivityTask"]["Catch"] == a["ActivityTask"]["Catch"]
    assert b["ActivityTask"]["TimeoutSeconds"] == 120
    assert b["ActivityTask"]["Parameters"]["Payload"]["layers"] == a["ContextTask"]["Parameters"]["Payload"]["layers"]
    # Evaluate the two result projections: original downstream JSON paths still
    # carry the same response objects, without a second Lambda invocation.
    response = {"activity": {"url_activity_state": "ACCESSIBLE", "skip_judgment": False},
                "context": {"final_key": "records/job/1/final/context.json", "skip_judgment": False}}
    projected_activity = {k.removesuffix(".$"): response[p.removeprefix("$.Payload.")]
                          for k, p in b["ActivityTask"]["ResultSelector"].items()}
    projected_context = {k.removesuffix(".$"): projected_activity[p.removeprefix("$.activity.")]
                         for k, p in b["ContextTask"]["Parameters"].items()}
    assert projected_activity["decision"] == response["activity"]
    assert projected_context["ctx"] == response["context"]
    assert b["ContextTask"]["Type"] == "Pass"


def test_different_input_cannot_be_silently_combined():
    original = fast_definition(source(DIRECT), **ARNS)
    original["States"]["ActivityTask"]["Parameters"]["Payload"]["url.$"] = "$.other_url"
    with pytest.raises(ValueError, match="same_activity_context_input_required"):
        patch_definition(original, context_arn=ARNS["context_arn"])
