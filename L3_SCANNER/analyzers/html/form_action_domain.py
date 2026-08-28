"""L3-H-03 Form Action Domain: 폼 목적지와 현재 등록 도메인의 관계 관측."""

from __future__ import annotations

from typing import Any, Mapping

from ...models.signal import signal_result
from ...policies.detection import DetectionPolicy
from ...utils.url import etld1

from ._common import fatal_html_error


def analyze(
    raw: Mapping[str, Any], document_url: str, policy: DetectionPolicy | None = None
) -> dict[str, Any]:
    """각 Form Action의 eTLD+1 일치 여부를 계산해 Evidence로 반환한다.

    명세에 H-03의 최종 ``detected`` 매핑이 아직 없으므로 같은 도메인/외부 도메인이
    관측되어도 판정을 발명하지 않고 항상 ``None``으로 둔다.
    """
    del policy
    fatal = fatal_html_error(raw)
    if fatal:
        return signal_result(
            "L3-H-03",
            "html",
            "form_action_domain",
            status="error",
            detected=None,
            error=fatal,
        )
    forms = list(raw.get("forms", []))
    if not forms:
        return signal_result(
            "L3-H-03",
            "html",
            "form_action_domain",
            status="not_applicable",
            detected=None,
            evidence={"forms": []},
        )
    current = etld1(document_url)
    observations = []
    for form in forms:
        destination = form.get("action_etld1")
        observations.append(
            {
                "form_id": form.get("form_id"),
                "action_url": form.get("action_url"),
                "action_etld1": destination,
                "current_etld1": current,
                "domain_match": destination == current
                if destination is not None and current is not None
                else None,
                "action_resolution": form.get("action_resolution"),
            }
        )
    first = observations[0]
    evidence = {
        **{
            key: first[key]
            for key in ("action_url", "action_etld1", "current_etld1", "domain_match")
        },
        "forms": observations,
    }
    return signal_result(
        "L3-H-03",
        "html",
        "form_action_domain",
        status="evaluated",
        detected=None,
        evidence=evidence,
    )
