"""독립 수집과 외부 콘텐츠 분석이 함께 사용하는 L3 입력 계약.

수집 경로가 달라도 Parser 이후 단계가 동일한 자료형만 보도록 만드는 것이 이
모듈의 목적이다. 이 모델은 입력을 정규화할 뿐, URL의 위험도나 Signal 판정을
수행하지 않는다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Mapping


@dataclass(slots=True)
class HTMLInput:
    """분석할 HTML 본문과 수집 당시의 응답 메타데이터.

    ``content=None``은 빈 HTML이 아니라 본문을 확보하지 못했다는 뜻이다.
    ``truncated=True``이면 일부 본문만 존재하므로 음성 관측을 확정해서는 안 된다.
    """

    content: str | None
    content_type: str | None = None
    encoding: str | None = None
    truncated: bool = False

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | None) -> "HTMLInput":
        """사전 입력을 기본값이 채워진 ``HTMLInput``으로 변환한다."""
        value = value or {}
        return cls(
            content=value.get("content"),
            content_type=value.get("content_type"),
            encoding=value.get("encoding"),
            truncated=bool(value.get("truncated", False)),
        )


@dataclass(slots=True)
class ScriptInput:
    """인라인 또는 외부 JavaScript 한 개의 공통 입력 표현.

    외부 스크립트는 URL만 보존되고 ``source``가 없을 수 있다. Source 부재나
    잘림은 정상적인 제한 수집 결과이므로 ``collection_errors``와 함께 downstream에
    그대로 전달한다.
    """

    script_id: str
    type: Literal["inline", "external"]
    source_url: str | None = None
    source: str | None = None
    sha256: str | None = None
    size: int | None = None
    truncated: bool = False
    collection_errors: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ScriptInput":
        """필수 식별자를 보존하며 사전 데이터를 스크립트 입력으로 변환한다."""
        return cls(
            script_id=str(value["script_id"]),
            type=value["type"],
            source_url=value.get("source_url"),
            source=value.get("source"),
            sha256=value.get("sha256"),
            size=value.get("size"),
            truncated=bool(value.get("truncated", False)),
            collection_errors=list(value.get("collection_errors", [])),
        )


@dataclass(slots=True)
class L3Input:
    """L3의 두 진입점이 공유하는 최상위 입력 모델.

    ``original_url``은 최초 요청 대상, ``document_url``은 리다이렉트 등이 반영된
    실제 문서 URL이다. L2 전용 모델은 이 계층으로 유입하지 않고 별도 Adapter에서
    이 계약으로 변환해야 한다.
    """

    original_url: str
    document_url: str
    html: HTMLInput
    scripts: list[ScriptInput] = field(default_factory=list)
    collection_errors: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "L3Input":
        """외부 매핑을 중첩 모델까지 포함한 ``L3Input``으로 정규화한다."""
        return cls(
            original_url=str(value["original_url"]),
            document_url=str(value.get("document_url") or value["original_url"]),
            html=HTMLInput.from_mapping(value.get("html")),
            scripts=[
                ScriptInput.from_mapping(item) for item in value.get("scripts", [])
            ],
            collection_errors=list(value.get("collection_errors", [])),
        )
