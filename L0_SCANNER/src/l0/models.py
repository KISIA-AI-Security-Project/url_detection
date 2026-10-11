"""Positive URL observations; execution errors stay outside observations."""
from dataclasses import dataclass, field
from typing import Any
from l0.common import JUDGMENT_HINTS

@dataclass
class CheckResult:
    observations: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)

def observation(name: str, facts: dict[str, Any]) -> dict[str, Any]:
    return {"검사": name, "관찰": facts, "판단에 쓸 점": JUDGMENT_HINTS[name]}

def analysis_error(name: str, code: str, *, target=None, error=None):
    result = {"code": code, "stage": name, "impact_scope": "analysis", "target": target}
    if error is not None:
        result.update(error_type=type(error).__name__, message=str(error))
    return result
