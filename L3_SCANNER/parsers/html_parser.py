"""HTML을 한 번만 파싱해 공유 Raw Observation을 만드는 공개 진입점."""

from __future__ import annotations

from typing import Any

from bs4 import BeautifulSoup

from .html.document import initialize_raw, populate_document
from .html.forms import build_forms
from .html.navigation import apply_base, build_meta_refresh
from .html.resources import build_resources


def parse_html(
    content: str | None, document_url: str, *, truncated: bool = False
) -> dict[str, Any]:
    """HTML을 한 번 파싱하고 모든 HTML Analyzer가 공유할 메타데이터를 조립한다.

    파싱 실패도 표준 Raw 구조와 오류로 반환한다. 하위 Builder는 DOM을 재파싱하지
    않고 동일한 ``BeautifulSoup`` 객체를 받아 각자의 관측 영역만 채운다.
    """
    raw = initialize_raw(content, document_url, truncated=truncated)
    if content is None:
        raw["errors"].append(
            {"code": "missing_html", "message": "HTML content is unavailable"}
        )
        return raw
    if not isinstance(content, str):
        raw["errors"].append(
            {"code": "invalid_html_type", "message": "HTML content must be text"}
        )
        return raw

    try:
        soup = BeautifulSoup(content, "lxml")
    # 외부 HTML은 파서 내부에서 다양한 예외를 낼 수 있다. 이 경계에서 구조화해
    # 개별 Signal 오류로 전파하되, 예외를 HTML 부재로 오인하지 않는다.
    except Exception as exc:  # 신뢰할 수 없는 입력을 구조화 오류로 바꾸는 파서 경계
        raw["errors"].append(
            {
                "code": "html_parse_error",
                "message": str(exc),
                "exception": type(exc).__name__,
            }
        )
        return raw

    populate_document(raw, soup)
    effective_base = apply_base(raw, soup, document_url)
    build_forms(raw, soup, document_url, effective_base)
    build_resources(raw, soup, effective_base)
    build_meta_refresh(raw, soup, effective_base)
    return raw
