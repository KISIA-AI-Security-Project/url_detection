"""통합 스캔 결과의 직렬화 계약."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from url_collector import PageSnapshot


@dataclass(frozen=True, slots=True)
class LayerError:
    """한 계층의 실행 실패를 다른 계층과 분리해 기록한다."""

    layer: str
    error_type: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "layer": self.layer,
            "error_type": self.error_type,
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class UnifiedScanResult:
    """공통 수집 메타데이터와 독립된 L2/L3 결과 묶음."""

    snapshot: PageSnapshot
    l2: dict[str, Any] | None
    l3: dict[str, Any] | None
    errors: tuple[LayerError, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "target": {
                "original_url": self.snapshot.original_url,
                "final_url": self.snapshot.final_url,
            },
            "collection": self.snapshot.metadata(),
            "layers": {"l2": self.l2, "l3": self.l3},
            "errors": [error.to_dict() for error in self.errors],
        }
