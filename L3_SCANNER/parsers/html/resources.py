"""이미지·Favicon·Open Graph·Script 리소스 메타데이터 Builder."""

from typing import Any

from bs4 import BeautifulSoup, Tag

from ...utils.hashing import sha256_text
from ...utils.url import etld1, resolve_http_url
from .common import stable_ids

_URL_OPEN_GRAPH_PROPERTIES = {
    "og:image",
    "og:image:url",
    "og:url",
    "og:video",
    "og:audio",
}


def build_resources(
    raw: dict[str, Any], soup: BeautifulSoup, effective_base: str
) -> None:
    """한 DOM에서 브랜드/JavaScript 분석에 필요한 리소스 관측값을 채운다."""
    _append_images(raw, soup, effective_base)
    _append_favicon(raw, soup, effective_base)
    _append_open_graph(raw, soup, effective_base)
    _append_scripts(raw, soup, effective_base)


def _append_images(raw: dict[str, Any], soup: BeautifulSoup, base: str) -> None:
    """이미지 URL을 공통 base 규칙으로 해석하고 안정적 식별자와 함께 기록한다."""
    images = [item for item in soup.find_all("img") if isinstance(item, Tag)]
    image_ids = stable_ids(images, "image")
    for image in images:
        src_raw = _optional_attribute(image, "src")
        src_url = resolve_http_url(src_raw, base)
        raw["images"].append(
            {
                "image_id": image_ids[id(image)],
                "src_raw": src_raw,
                "resource_url": src_url,
                "resource_domain": etld1(src_url),
                "alt": _optional_attribute(image, "alt"),
            }
        )


def _append_favicon(raw: dict[str, Any], soup: BeautifulSoup, base: str) -> None:
    """첫 icon link의 원문 URL, 절대 URL, 등록 도메인을 기록한다."""
    favicon = soup.find("link", rel=_rel_contains_icon)
    if not isinstance(favicon, Tag):
        return
    href_raw = _optional_attribute(favicon, "href")
    favicon_url = resolve_http_url(href_raw, base)
    raw["favicon"] = {
        "raw_href": href_raw,
        "resource_url": favicon_url,
        "resource_domain": etld1(favicon_url),
    }


def _append_open_graph(raw: dict[str, Any], soup: BeautifulSoup, base: str) -> None:
    """Open Graph 값을 보존하고 URL 속성만 리소스 URL로 추가 해석한다."""
    for meta in soup.find_all("meta"):
        if not isinstance(meta, Tag):
            continue
        property_name = str(meta.get("property") or "").strip().lower()
        if not property_name.startswith("og:"):
            continue
        value = _optional_attribute(meta, "content")
        raw["open_graph"][property_name] = {
            "raw_content": value,
            "resource_url": (
                resolve_http_url(value, base)
                if property_name in _URL_OPEN_GRAPH_PROPERTIES
                else None
            ),
        }


def _append_scripts(raw: dict[str, Any], soup: BeautifulSoup, base: str) -> None:
    """스크립트 순서와 Source 확보 여부를 보존하는 입력 메타데이터를 만든다.

    외부 ``src``는 URL만 기록하며 여기서 네트워크 요청을 하지 않는다. 인라인 Source는
    JavaScript Parser로 한 번 전달하고 결과 Raw에는 해시·크기 중심으로 보존된다.
    """
    scripts = [item for item in soup.find_all("script") if isinstance(item, Tag)]
    for index, script in enumerate(scripts, 1):
        script_id = f"script-{index}"
        src_raw = _optional_attribute(script, "src")
        media_type = _optional_attribute(script, "type")
        if src_raw is not None:
            raw["scripts"].append(
                {
                    "script_id": script_id,
                    "type": "external",
                    "source_url": resolve_http_url(src_raw, base),
                    "raw_source_url": src_raw,
                    "source": None,
                    "sha256": None,
                    "size": None,
                    "truncated": False,
                    "collection_errors": [],
                    "media_type": media_type,
                }
            )
            continue
        source = script.string if script.string is not None else script.get_text()
        raw["scripts"].append(
            {
                "script_id": script_id,
                "type": "inline",
                "source_url": None,
                "source": source,
                "sha256": sha256_text(source),
                "size": len(source.encode("utf-8")),
                "truncated": False,
                "collection_errors": [],
                "media_type": media_type,
            }
        )


def _rel_contains_icon(value: object) -> bool:
    """문자열 또는 토큰 목록 형태의 rel 속성에 ``icon``이 있는지 확인한다."""
    if isinstance(value, str):
        tokens = value.lower().split()
    elif isinstance(value, (list, tuple)):
        tokens = [str(item).lower() for item in value]
    else:
        return False
    return "icon" in tokens


def _optional_attribute(element: Tag, name: str) -> str | None:
    """HTML 속성 부재를 ``None``으로 유지하며 문자열로 변환한다."""
    value = element.get(name)
    return str(value) if value is not None else None
