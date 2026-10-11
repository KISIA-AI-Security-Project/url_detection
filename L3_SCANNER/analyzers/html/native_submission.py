"""Analyze native form-data eligibility from captured attributes only.

This is L3 analysis, not context formatting or a URL-risk classifier. Historical
raw can be analyzed through this same entry point without collecting a new page.
"""

from hashlib import sha256
import json

ANALYZER_VERSION = "1.0.0"


def native_participation(field):
    """Known exclusions take precedence; unrecorded conditions remain unknown."""
    kind = (
        str(field.get("type") or "").lower()
        if field.get("tag") in (None, "input")
        else ""
    )
    if field.get("disabled") is True:
        return "excluded_disabled"
    if kind in ("button", "reset"):
        return "excluded_non_submit_control"
    if kind == "image":
        return "coordinates_only_if_activated_submitter"
    if "name" not in field:
        return "unknown_name_not_recorded"
    if field["name"] is None or field["name"] == "":
        return "excluded_missing_name"
    if field.get("disabled") is not False:
        return "unknown_disabled_state_not_recorded"
    if kind in ("checkbox", "radio"):
        if field.get("checked") is False:
            return "excluded_unchecked"
        return "conditional_checked_state_required"
    if kind == "submit":
        return "conditional_activated_submitter_required"
    return "candidate_under_recorded_attributes_only"


EXPLANATIONS = {
    "excluded_disabled": "The recorded disabled control contributes no native form-data entry.",
    "excluded_non_submit_control": "A button/reset input contributes no native field-value entry.",
    "coordinates_only_if_activated_submitter": "An activated image submitter can contribute coordinates without a name; this is conditional on other form rules.",
    "unknown_name_not_recorded": "Name was not captured, so name-based eligibility is unknown.",
    "excluded_missing_name": "The ordinary control has no nonempty name and contributes no native form-data entry.",
    "unknown_disabled_state_not_recorded": "Disabled state was not captured, so enabled-state eligibility is unknown.",
    "excluded_unchecked": "The recorded unchecked radio/checkbox contributes no native form-data entry.",
    "conditional_checked_state_required": "Native inclusion depends on checked state and other form conditions.",
    "conditional_activated_submitter_required": "Native inclusion requires this control to be the activated submitter and other form conditions to hold.",
    "candidate_under_recorded_attributes_only": "Recorded name and enabled state allow a candidate entry; unrecorded form conditions can still exclude it.",
}


def analyze_native_submission(html_raw):
    """Return source-bound analysis facts, never observed execution or a verdict."""
    if not html_raw.get("inputs"):
        return []
    source_hash = sha256(
        json.dumps(
            html_raw, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()
    fields = []
    for index, field in enumerate(html_raw["inputs"]):
        state = native_participation(field)
        fields.append(
            {
                "field_id": field.get("field_id"),
                "form_id": field.get("form_id"),
                "source_pointer": f"/html/inputs/{index}",
                "status": state,
                "explanation": EXPLANATIONS[state],
            }
        )
    return [
        {
            "id": "L3-native-submission",
            "kind": "native_form_submission",
            "analyzer": {"name": "native_submission", "version": ANALYZER_VERSION},
            "source": {"pointer": "/html", "sha256": source_hash},
            "fields": fields,
            "execution_observed": False,
            "scope": "Native entry-list rules on captured static attributes before runtime changes; not a JavaScript data-flow analysis.",
            "limitations": [
                "Form ownership, ancestor disabled fieldsets/datalist, selected options, validation, activation and handlers are not fully established by these captured attributes.",
                "Native exclusion does not prevent separate JavaScript from reading or sending the same value.",
            ],
        }
    ]
