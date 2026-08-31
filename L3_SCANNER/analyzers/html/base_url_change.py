"""L3-H-08 Base URL Change: 외부 등록 도메인을 가리키는 base 요소 관측."""

from __future__ import annotations

from typing import Any, Mapping

from L3_SCANNER.models.signal import signal_result
from L3_SCANNER.policies.detection import DetectionPolicy
from L3_SCANNER.utils.url import etld1

from ._common import fatal_html_error


def analyze(
    raw: Mapping[str, Any], document_url: str, policy: DetectionPolicy | None = None
) -> dict[str, Any]:
    """유효한 ``<base href>``와 현재 문서의 eTLD+1을 비교한다.

    base가 없으면 정상 평가된 음성이다. 반면 URL 또는 등록 도메인을 해석할 수 없으면
    ``external=None``을 그대로 사용해 외부가 아니라는 잘못된 결론을 피한다.
    """
    del policy
    fatal = fatal_html_error(raw)
    if fatal:
        return signal_result(
            "L3-H-08",
            "html",
            "base_url_change",
            status="error",
            detected=None,
            error=fatal,
        )
    base = raw.get("base")
    if base is None:
        return signal_result(
            "L3-H-08",
            "html",
            "base_url_change",
            status="evaluated",
            detected=False,
            evidence={"base_url": None, "base_etld1": None, "external": None},
        )
    current = etld1(document_url)
    base_domain = base.get("base_etld1")
    external = (
        base_domain != current
        if base.get("valid") and base_domain is not None and current is not None
        else None
    )
    return signal_result(
        "L3-H-08",
        "html",
        "base_url_change",
        status="evaluated",
        detected=external,
        evidence={
            "base_url": base.get("base_url"),
            "base_etld1": base_domain,
            "external": external,
        },
    )
