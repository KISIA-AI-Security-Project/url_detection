"""제한형 JavaScript 데이터 흐름 분석에서만 사용하는 내부 값 모델."""

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class Taint:
    """실제 값 없이 Credential Source의 구조적 출처만 운반하는 표식.

    민감한 입력값은 저장하지 않으며, Source event와 변환 단계만 Network Sink까지
    전파해 L3-J-06의 명시적 Source-Sink 관계를 구성한다.
    """

    credential_type: str
    field_id: str
    source_event_id: str
    transformations: tuple[str, ...] = ()


@dataclass(slots=True)
class Element:
    """정적 분석 중 추적하는 DOM 요소의 최소 구조 표현."""

    field: dict[str, Any] | None = None
    is_script: bool = False
    source_url: str | None = None


@dataclass(slots=True)
class Eval:
    """표현식 평가에서 전파할 리터럴·taint·DOM·decode 계보의 묶음.

    이는 JavaScript를 실제 실행한 결과가 아니라 AST를 따라 계산한 제한적 정적
    메타데이터다.
    """

    literal: Any = None
    taints: list[Taint] = field(default_factory=list)
    element: Element | None = None
    decode_lineage: list[dict[str, str]] = field(default_factory=list)


def unique_taints(values: list[Taint]) -> list[Taint]:
    """동일 Source와 변환 경로를 가진 taint를 최초 순서대로 중복 제거한다."""
    seen: set[tuple[Any, ...]] = set()
    result = []
    for value in values:
        key = (
            value.credential_type,
            value.field_id,
            value.source_event_id,
            value.transformations,
        )
        if key not in seen:
            seen.add(key)
            result.append(value)
    return result


def unique_lineage(values: list[dict[str, str]]) -> list[dict[str, str]]:
    """Decode event와 method 조합을 최초 순서대로 중복 제거한다."""
    seen: set[tuple[str, str]] = set()
    result = []
    for value in values:
        key = (value["event_id"], value["method"])
        if key not in seen:
            seen.add(key)
            result.append(value)
    return result
