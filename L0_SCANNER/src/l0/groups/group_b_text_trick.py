"""Split words and IDN character conversions without brand heuristics."""
import re
import unicodedata
from l0.common import GROUP_B_WORD_SPLIT, GROUP_B_IDN_CONVERSION
from l0.models import CheckResult, observation, analysis_error
from l0.parsing import ParseResult
from l0.data.confusables import CONFUSABLE_MAP

def _decode_label(label: str) -> str:
    return label[4:].encode("ascii").decode("punycode") if label.startswith("xn--") else label

def check_host_word_split(result: ParseResult) -> CheckResult:
    parsed, extracted = result.parsed, result.extracted
    if not parsed or not extracted or parsed.host_type in {"IPV4", "IPV6"}:
        return CheckResult()
    labels = [("서브도메인", i, label) for i, label in enumerate(extracted.subdomain.split(".")) if label]
    if extracted.domain:
        labels.append(("등록 도메인의 이름 부분", 0, extracted.domain))
    records = []
    for location, index, label in labels:
        try:
            text = _decode_label(label)
        except (UnicodeError, ValueError):
            # The IDN check reports this decode failure.
            continue
        words = [word for word in re.split(r"[-_]", text) if word]
        if len(words) < 2:
            continue
        records.append(observation(GROUP_B_WORD_SPLIT, {
            "호스트": parsed.hostname, "등록_도메인": extracted.registered_domain,
            "위치": location, "부분_순번": index,
            "원래_부분": text, "구분자": "".join(dict.fromkeys(c for c in text if c in "-_")),
            "분리된_단어": words,
        }))
    return CheckResult(records)

def _skeleton(text: str) -> str:
    decomposed = unicodedata.normalize("NFKD", text)
    stripped = "".join(c for c in decomposed if not unicodedata.combining(c))
    return "".join(CONFUSABLE_MAP.get(c, c) for c in stripped).lower()

def check_idn_conversion(result: ParseResult) -> CheckResult:
    if not result.parsed or result.parsed.host_type in {"IPV4", "IPV6"}:
        return CheckResult()
    decoded, comparison, errors = [], [], []
    changed = False
    for index, label in enumerate(result.parsed.hostname.split(".")):
        try:
            original = _decode_label(label)
        except (UnicodeError, ValueError) as exc:
            errors.append(analysis_error(GROUP_B_IDN_CONVERSION, "idn_decode_failed",
                                         target={"label": label, "label_index": index}, error=exc))
            original = label
        folded = _skeleton(original) if label.startswith("xn--") and original != label else original
        changed = changed or folded != original
        decoded.append(original)
        comparison.append(folded)
    records = []
    if changed:
        records.append(observation(GROUP_B_IDN_CONVERSION, {
            # Same host as raw.parsed.hostname, displayed in Unicode for comparison.
            "실제_접속_호스트": ".".join(decoded), "비교용_표기": ".".join(comparison),
        }))
    return CheckResult(records, errors)

GROUP_B_DETECTORS = (check_host_word_split, check_idn_conversion)
