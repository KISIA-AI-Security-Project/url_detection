"""Run ten deterministic L0 checks and emit positive compact records only."""
from copy import deepcopy
import unicodedata
from l0.common import JUDGMENT_GUIDANCE
from l0.models import CheckResult, analysis_error
from l0.parsing import ParseResult, ParseStatus, parse_url_stage
from l0.groups.group_a_host import GROUP_A_DETECTORS
from l0.groups.group_b_text_trick import GROUP_B_DETECTORS
from l0.groups.group_c_link_file import GROUP_C_DETECTORS
from l0.groups.group_d_parameter import GROUP_D_DETECTORS
from l0.groups.group_e_string import GROUP_E_DETECTORS
from l0.data.free_hosting import FREE_HOSTING_VERSION
from l0.data.tld_lists import TLD_BLACK_VERSION
from l0.data.extensions import EXTENSION_RISK_VERSION
from l0.data.shorteners import SHORTENERS_VERSION
from l0.data.confusables import CONFUSABLES_VERSION

PRODUCER_CONTRACT = "url-observations-3"
ALL_DETECTORS = (*GROUP_A_DETECTORS, *GROUP_B_DETECTORS, *GROUP_C_DETECTORS,
                 *GROUP_D_DETECTORS, *GROUP_E_DETECTORS)

def run_detectors(result: ParseResult) -> CheckResult:
    output = CheckResult()
    for detector in ALL_DETECTORS:
        try:
            checked = detector(result)
        except Exception as exc:
            checked = CheckResult(errors=[analysis_error(detector.__name__, "evaluator_exception", error=exc)])
        output.observations.extend(checked.observations)
        for index, error in enumerate(checked.errors):
            error.setdefault("occurrence_id", f"l0:{detector.__name__}:{index}")
            output.errors.append(error)
    return output

def analyze(raw_url: str) -> dict:
    result = parse_url_stage(raw_url)
    for index, error in enumerate(result.query_errors):
        error.update(occurrence_id=f"l0:query:{index}", stage="query_parsing",
                     code="query_component_parse_failed", impact_scope="analysis", url=raw_url)
    output = {
        **result.to_dict(), "producer_contract": PRODUCER_CONTRACT,
        "observations": [], "errors": [],
        "judgment_guidance": deepcopy(JUDGMENT_GUIDANCE),
        "reference_versions": {
            "tld_black": TLD_BLACK_VERSION, "free_hosting": FREE_HOSTING_VERSION,
            "shorteners": SHORTENERS_VERSION, "extension_risk": EXTENSION_RISK_VERSION,
            "confusables": CONFUSABLES_VERSION, "unicodedata": unicodedata.unidata_version,
        },
    }
    if result.parse_status is not ParseStatus.SUCCESS:
        output["analysis_execution"] = {"state": "not_run", "reason": "url_parse_not_successful",
                                        "parse_status": result.parse_status.value}
        return output
    checked = run_detectors(result)
    output.update(observations=checked.observations, errors=checked.errors,
                  analysis_execution={"state": "run", "check_count": len(ALL_DETECTORS),
                                      "record_count": len(checked.observations)})
    return output
