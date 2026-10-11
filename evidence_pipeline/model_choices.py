"""Server-owned Claude choices and immutable per-attempt model selection.

The public client sends only a choice ID. No endpoint, credentials, or arbitrary
provider/model options are accepted from it. A configured entry is an operator
declaration of availability, not evidence of a successful live provider call.
"""
from copy import deepcopy
from hashlib import sha256
import json
import math
import os
import re


CHOICE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
EFFORTS = (None, "low", "medium", "high", "xhigh", "max")
_UNSPECIFIED = object()


class ModelChoiceError(ValueError):
    pass


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ModelChoiceError("invalid_model_configuration")
        result[key] = value
    return result


def _profile(value):
    allowed = {"label", "provider", "model", "timeout", "max_tokens", "output_effort", "omit_temperature"}
    if type(value) is not dict or set(value) - allowed or not {"label", "provider", "model"} <= value.keys():
        raise ModelChoiceError("invalid_model_configuration")
    provider, model, label = (value.get(key) for key in ("provider", "model", "label"))
    if (provider not in ("anthropic", "bedrock") or type(model) is not str or
            not re.fullmatch(r"(?:[a-z0-9-]+\.)*claude-[A-Za-z0-9._:-]+", model) or
            type(label) is not str or not label.strip() or len(label) > 120):
        raise ModelChoiceError("invalid_model_configuration")
    timeout = value.get("timeout", 120 if provider == "bedrock" else 50)
    max_tokens = value.get("max_tokens", 8192)
    effort = value.get("output_effort")
    omit = value.get("omit_temperature", provider == "bedrock")
    if (type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 900 or
            type(max_tokens) is not int or not 0 < max_tokens <= 32768 or
            effort not in EFFORTS or type(omit) is not bool or
            (provider == "bedrock" and not omit)):
        raise ModelChoiceError("invalid_model_configuration")
    return {"label": label.strip(), "provider": provider, "model": model,
            "timeout": float(timeout), "max_tokens": max_tokens,
            "output_effort": effort, "omit_temperature": omit}


def _configured_profile(value):
    if type(value) is not dict:
        raise ModelChoiceError("invalid_model_configuration")
    profile = _profile({key: item for key, item in value.items() if key != "efforts"})
    efforts = value.get("efforts", [profile["output_effort"]] if profile["output_effort"] is not None else [])
    if (type(efforts) is not list or any(type(item) is not str or item not in EFFORTS for item in efforts)
            or len(efforts) != len(set(efforts))
            or (profile["output_effort"] is None and efforts)
            or (profile["output_effort"] is not None and profile["output_effort"] not in efforts)):
        raise ModelChoiceError("invalid_model_configuration")
    return {**profile, "efforts": list(efforts)}


def model_configuration(environ=None):
    env = os.environ if environ is None else environ
    encoded = env.get("FAST_MODEL_CHOICES_JSON")
    try:
        if encoded:
            value = json.loads(encoded, object_pairs_hook=_unique_pairs)
        else:
            model = env.get("JUDGMENT_MODEL")
            if not model:
                raise ModelChoiceError("model_choices_unavailable")
            provider = env.get("JUDGMENT_PROVIDER", "anthropic")
            value = {"default_model_choice": "configured", "models": {"configured": {
                "label": model, "provider": provider, "model": model,
                "timeout": float(env.get("LLM_TIMEOUT_SECONDS", "120" if provider == "bedrock" else "50")),
                "max_tokens": int(env.get("JUDGMENT_MAX_TOKENS", "8192")),
                "output_effort": env.get("ANTHROPIC_OUTPUT_EFFORT") or None,
                "omit_temperature": provider == "bedrock" or env.get("ANTHROPIC_OMIT_TEMPERATURE", "0") == "1"}}}
        if type(value) is not dict or set(value) != {"default_model_choice", "models"}:
            raise ModelChoiceError("invalid_model_configuration")
        models = value["models"]
        if type(models) is not dict or not models or len(models) > 32:
            raise ModelChoiceError("invalid_model_configuration")
        if any(type(key) is not str or not CHOICE.fullmatch(key) for key in models):
            raise ModelChoiceError("invalid_model_configuration")
        default = value["default_model_choice"]
        if type(default) is not str or default not in models:
            raise ModelChoiceError("invalid_model_configuration")
        return {"default_model_choice": default, "models": {key: _configured_profile(profile) for key, profile in models.items()}}
    except ModelChoiceError:
        raise
    except (TypeError, ValueError, OverflowError):
        raise ModelChoiceError("invalid_model_configuration") from None


def public_model_choices(environ=None):
    config = model_configuration(environ)
    return {"default_model_choice": config["default_model_choice"],
            "models": [{"id": key, "label": profile["label"], "efforts": profile["efforts"],
                        "default_effort": profile["output_effort"]} for key, profile in config["models"].items()]}


def select_model(choice, environ=None, *, reasoning_effort=_UNSPECIFIED):
    if type(choice) is not str or not CHOICE.fullmatch(choice):
        raise ModelChoiceError("invalid_model_choice")
    config = model_configuration(environ)
    if choice not in config["models"]:
        raise ModelChoiceError("unsupported_model_choice")
    profile = deepcopy(config["models"][choice])
    efforts = profile.pop("efforts")
    if reasoning_effort is not _UNSPECIFIED:
        if type(reasoning_effort) is not str or reasoning_effort not in EFFORTS:
            raise ModelChoiceError("invalid_reasoning_effort")
        if reasoning_effort not in efforts:
            raise ModelChoiceError("unsupported_reasoning_effort")
        profile["output_effort"] = reasoning_effort
    return {"choice": choice, "profile": profile,
            "profile_sha256": sha256(_canonical(profile).encode("utf-8")).hexdigest()}


def validate_selection(value, *, environ=None, current=True):
    if type(value) is not dict or set(value) != {"choice", "profile", "profile_sha256"}:
        raise ModelChoiceError("invalid_model_selection")
    choice = value["choice"]
    if type(choice) is not str or not CHOICE.fullmatch(choice):
        raise ModelChoiceError("invalid_model_selection")
    profile = _profile(value["profile"])
    if (profile != value["profile"] or
            sha256(_canonical(profile).encode("utf-8")).hexdigest() != value["profile_sha256"]):
        raise ModelChoiceError("model_selection_hash_mismatch")
    if current:
        try:
            configured = select_model(choice, environ, **({"reasoning_effort": profile["output_effort"]}
                                      if profile["output_effort"] is not None else {}))
        except ModelChoiceError:
            raise ModelChoiceError("model_configuration_changed") from None
        if value != configured:
            raise ModelChoiceError("model_configuration_changed")
    return {**deepcopy(value), "profile": profile}


_UNREAD = object()


def bind_model_selection(event, store, job, attempt, *, existing_result=_UNREAD):
    """Called after input validation and before returning an existing result.

    Store.put is immutable and permits byte-identical replay only. A selection
    cannot be attached retroactively to a call that already claimed this attempt.
    """
    prefix = f"records/{job}/{attempt}/fast/"
    key = prefix + "model-selection.json"
    existing = store.get(key, optional=True)
    selection = event.get("model_selection")
    selection = {} if selection in (None, {}) else validate_selection(selection, current=False)
    if existing is not None:
        if existing != selection:
            raise ModelChoiceError("model_selection_attempt_mismatch")
        return
    # run_judgment already loaded the result with its parallel input reads.
    # Standalone callers can still ask this helper to perform that read.
    if existing_result is _UNREAD:
        existing_result = store.get(prefix + "result.json", optional=True)
    if existing_result is not None or store.get(prefix + "request-claim.json", optional=True) is not None:
        if selection:
            raise ModelChoiceError("model_selection_attempt_already_started")
        return  # Previously completed legacy attempts predate the binding file.
    store.put(key, selection)
