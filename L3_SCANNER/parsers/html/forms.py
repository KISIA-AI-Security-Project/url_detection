"""Form·Input·Button의 구조와 소속 관계를 만드는 Raw Builder."""

from typing import Any

from bs4 import BeautifulSoup, Tag

from L3_SCANNER.utils.url import etld1, resolve_http_url
from .common import stable_ids


def build_forms(
    raw: dict[str, Any],
    soup: BeautifulSoup,
    document_url: str,
    effective_base: str,
) -> None:
    """한 DOM에서 폼과 입력 요소를 추출하고 양방향 식별 관계를 연결한다."""
    form_tags = _tags(soup, "form")
    form_ids = stable_ids(form_tags, "form")
    html_form_ids = _html_form_ids(form_tags, form_ids)
    _append_forms(raw, form_tags, form_ids, document_url, effective_base)
    _append_inputs(raw, soup, form_ids, html_form_ids)
    _append_buttons(raw, soup, form_ids, html_form_ids)


def _tags(soup: BeautifulSoup, name: str) -> list[Tag]:
    """타입이 보장된 BeautifulSoup Tag 목록만 반환한다."""
    return [item for item in soup.find_all(name) if isinstance(item, Tag)]


def _html_form_ids(form_tags: list[Tag], form_ids: dict[int, str]) -> dict[str, str]:
    """HTML ``form`` 속성으로 외부 연결할 수 있도록 id 매핑을 만든다."""
    result: dict[str, str] = {}
    for form in form_tags:
        html_id = str(form.get("id") or "").strip()
        if html_id and html_id not in result:
            result[html_id] = form_ids[id(form)]
    return result


def _append_forms(
    raw: dict[str, Any],
    form_tags: list[Tag],
    form_ids: dict[int, str],
    document_url: str,
    effective_base: str,
) -> None:
    """폼 method/action을 동일 URL 규칙으로 정규화해 Raw에 추가한다.

    ``action``이 없거나 비어 있으면 HTML 규칙에 따라 현재 문서를 목적지로 본다.
    해석 실패는 외부가 아니라 ``invalid_or_non_http``로 남겨 Analyzer가 미확정으로
    처리할 수 있게 한다.
    """
    for form in form_tags:
        action_present = form.has_attr("action")
        action_raw = str(form.get("action")) if action_present else None
        if action_raw is None or not action_raw.strip():
            action_url = (
                document_url if resolve_http_url(document_url, document_url) else None
            )
            resolution = "implicit_document" if action_raw is None else "empty_document"
        else:
            action_url = resolve_http_url(action_raw, effective_base)
            resolution = "resolved" if action_url else "invalid_or_non_http"
        raw["forms"].append(
            {
                "form_id": form_ids[id(form)],
                "html_id": str(form.get("id")) if form.get("id") is not None else None,
                "name": str(form.get("name")) if form.get("name") is not None else None,
                "method": str(form.get("method") or "get").strip().lower() or "get",
                "action_present": action_present,
                "action_raw": action_raw,
                "action_url": action_url,
                "action_etld1": etld1(action_url),
                "action_resolution": resolution,
                "input_ids": [],
            }
        )


def _append_inputs(
    raw: dict[str, Any],
    soup: BeautifulSoup,
    form_ids: dict[int, str],
    html_form_ids: dict[str, str],
) -> None:
    """입력 필드 속성과 소속 폼을 기록하고 폼의 ``input_ids``도 갱신한다."""
    forms_by_id = {form["form_id"]: form for form in raw["forms"]}
    input_tags = _tags(soup, "input")
    input_ids = stable_ids(input_tags, "input")
    for input_tag in input_tags:
        form_id = _associated_form(input_tag, form_ids, html_form_ids)
        field = {
            "field_id": input_ids[id(input_tag)],
            "form_id": form_id,
            "type": str(input_tag.get("type") or "text").strip().lower() or "text",
            "name": _optional_attribute(input_tag, "name"),
            "html_id": _optional_attribute(input_tag, "id"),
            "placeholder": _optional_attribute(input_tag, "placeholder"),
            "autocomplete": _optional_attribute(input_tag, "autocomplete"),
            "disabled": input_tag.has_attr("disabled"),
            "readonly": input_tag.has_attr("readonly"),
            "hidden": str(input_tag.get("type") or "").strip().lower() == "hidden",
        }
        raw["inputs"].append(field)
        if form_id in forms_by_id:
            forms_by_id[form_id]["input_ids"].append(field["field_id"])


def _append_buttons(
    raw: dict[str, Any],
    soup: BeautifulSoup,
    form_ids: dict[int, str],
    html_form_ids: dict[str, str],
) -> None:
    """버튼의 기본 submit 의미와 소속 폼을 Raw Observation으로 기록한다."""
    button_tags = _tags(soup, "button")
    button_ids = stable_ids(button_tags, "button")
    for button in button_tags:
        raw["buttons"].append(
            {
                "button_id": button_ids[id(button)],
                "form_id": _associated_form(button, form_ids, html_form_ids),
                "type": str(button.get("type") or "submit").strip().lower(),
                "text": button.get_text(" ", strip=True),
            }
        )


def _associated_form(
    element: Tag, form_ids: dict[int, str], html_form_ids: dict[str, str]
) -> str | None:
    """명시적 ``form`` 속성을 우선해 요소가 속한 폼 식별자를 찾는다.

    폼 밖에 배치된 컨트롤도 HTML의 ``form=<id>`` 속성으로 연결될 수 있으므로 단순히
    부모 요소만 확인해서는 안 된다.
    """
    explicit_form = str(element.get("form") or "").strip()
    if explicit_form:
        return html_form_ids.get(explicit_form)
    parent = element.find_parent("form")
    return form_ids.get(id(parent)) if isinstance(parent, Tag) else None


def _optional_attribute(element: Tag, name: str) -> str | None:
    """속성 부재와 빈 문자열을 구분한 채 문자열 값으로 변환한다."""
    value = element.get(name)
    return str(value) if value is not None else None
