"""HTML 문서 단위 메타데이터와 초기 Raw 구조 생성."""

from typing import Any

from bs4 import BeautifulSoup, NavigableString

from ...models.raw import empty_html_raw
from ...utils.hashing import sha256_text
from ...utils.url import etld1


def initialize_raw(
    content: str | None, document_url: str, *, truncated: bool
) -> dict[str, Any]:
    """파싱 전에도 계약 형태가 유지되는 HTML Raw를 초기화한다.

    Source가 잘렸으면 해시와 크기는 보존하되 ``source_complete=False``를 기록한다.
    이후 음성 Signal은 전체 문서를 보지 못했으므로 미확정 상태로 승격된다.
    """
    raw = empty_html_raw()
    raw["scripts"] = []
    raw["document"] = {
        "url": document_url,
        "etld1": etld1(document_url),
        "title": None,
        "visible_text": "",
        "size": None,
        "sha256": None,
        "source_complete": not truncated,
        "parse_succeeded": False,
    }
    if content is not None:
        raw["document"]["size"] = len(content.encode("utf-8", errors="replace"))
        raw["document"]["sha256"] = sha256_text(content)
    if truncated:
        raw["errors"].append(
            {
                "code": "html_source_truncated",
                "message": "HTML source was truncated before parsing; negative observations are unresolved.",
            }
        )
    return raw


def populate_document(raw: dict[str, Any], soup: BeautifulSoup) -> None:
    """파싱 성공 상태, 제목, 사용자에게 보이는 텍스트를 문서 Raw에 기록한다.

    실행 코드나 스타일·템플릿 텍스트는 화면 본문이 아니므로 제외한다. 이 텍스트는
    브랜드 식별 정책 등에 제공되는 관측값이며 Parser가 브랜드를 판단하지는 않는다.
    """
    raw["document"]["parse_succeeded"] = True
    raw["document"]["title"] = (
        soup.title.get_text(" ", strip=True) if soup.title else None
    )
    raw["document"]["visible_text"] = " ".join(
        str(node).strip()
        for node in soup.find_all(string=True)
        if isinstance(node, NavigableString)
        and node.parent is not None
        and node.parent.name not in {"script", "style", "template", "noscript"}
        and str(node).strip()
    )
