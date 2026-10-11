"""Adapt a saved Activity + Context definition without changing result consumers.

This is an offline deployment builder. The selected Context version must support
``activity_context`` with a 55-second watchdog for each stage and a 110-second
outer Lambda limit before this definition is used. No AWS mutation occurs here.
"""
from copy import deepcopy
import re

from deployment.build_fast_result_candidate import _check_graph


def patch_definition(original, *, context_arn):
    if not re.fullmatch(
        r"arn:aws:lambda:ap-northeast-2:998301375101:function:team5-itg-[A-Za-z0-9_-]+:[1-9][0-9]*",
        context_arn,
    ):
        raise ValueError("explicit_project_context_version_required")
    result = deepcopy(original)
    states = result["States"]
    activity, context = states["ActivityTask"], states["ContextTask"]
    if not (
        activity["Type"] == context["Type"] == "Task"
        and activity["Resource"] == context["Resource"] == "arn:aws:states:::lambda:invoke"
        and activity["ResultPath"] == "$.activity"
        and activity["ResultSelector"] == {"decision.$": "$.Payload"}
        and activity["Next"] == "ActivityShape"
        and context["ResultPath"] == "$.context"
        and context["ResultSelector"] == {"ctx.$": "$.Payload"}
        and context["Next"] == "MarkContext"
        and activity.get("Catch") == context.get("Catch")
        and not activity.get("Retry") and not context.get("Retry")
        and activity.get("TimeoutSeconds") == context.get("TimeoutSeconds") == 60
    ):
        raise ValueError("reviewed_activity_context_state_contract_required")
    activity_payload = activity["Parameters"]["Payload"]
    context_payload = context["Parameters"]["Payload"]
    if activity_payload != {
        **{k: v for k, v in context_payload.items() if k != "url_activity.$"},
        "operation": "activity",
    } or context_payload.get("url_activity.$") != "$.activity.decision":
        raise ValueError("same_activity_context_input_required")
    activity["Parameters"]["FunctionName"] = context_arn
    activity_payload["operation"] = "activity_context"
    activity["ResultSelector"] = {
        "decision.$": "$.Payload.activity", "ctx.$": "$.Payload.context",
    }
    activity["TimeoutSeconds"] += context["TimeoutSeconds"]
    activity["Comment"] = (
        "Read and validate the shared input once, persist Activity, then build Context. "
        "Both saved outputs retain their original contracts; the qualified "
        "handler must enforce separate 55-second Activity and Context limits."
    )
    states["ContextTask"] = {
        "Type": "Pass", "Parameters": {"ctx.$": "$.activity.ctx"},
        "ResultPath": "$.context", "Next": "MarkContext",
        "Comment": "Expose the already saved Context response at its original path.",
    }
    _check_graph(result)
    return result
