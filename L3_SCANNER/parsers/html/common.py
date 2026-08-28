"""여러 HTML Raw Builder가 공유하는 안정적 요소 식별자 도우미."""

from bs4 import Tag


def stable_ids(elements: list[Tag], prefix: str) -> dict[int, str]:
    """고유한 HTML ``id``를 사용하고 중복 시 결정적인 DOM 순번으로 대체한다.

    작성자가 중복 ``id``를 사용한 문서에서 서로 다른 요소가 같은 증거 식별자로
    합쳐지는 것을 방지한다. 반환 키는 파싱 중인 Tag 객체의 identity다.
    """
    counts: dict[str, int] = {}
    for element in elements:
        html_id = str(element.get("id") or "").strip()
        if html_id:
            counts[html_id] = counts.get(html_id, 0) + 1
    return {
        id(element): (
            str(element.get("id")).strip()
            if str(element.get("id") or "").strip()
            and counts[str(element.get("id")).strip()] == 1
            else f"{prefix}-{index}"
        )
        for index, element in enumerate(elements, 1)
    }
