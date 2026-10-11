"""공통 수집 계층의 구조화 오류 모델."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class CollectionError:
    """부분 수집 실패를 예외 대신 스냅샷에 보존하는 불변 오류."""

    stage: str
    code: str
    message: str
    details: tuple[tuple[str, Any], ...] = field(default_factory=tuple)

    @classmethod
    def create(
        cls,
        stage: str,
        code: str,
        message: str,
        **details: Any,
    ) -> "CollectionError":
        """직렬화 가능한 상세 정보를 안정적인 순서로 저장한다."""
        return cls(stage, code, message, tuple(sorted(details.items())))

    def to_dict(self) -> dict[str, Any]:
        """L2/L3 결과에 넣을 공통 사전 표현을 반환한다."""
        return {
            "stage": self.stage,
            "code": self.code,
            "message": self.message,
            "details": dict(self.details),
        }
