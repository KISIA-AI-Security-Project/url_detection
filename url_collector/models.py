"""L2와 L3가 함께 소비하는 불변 HTTP 페이지 스냅샷 계약."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .errors import CollectionError
from .policy import CollectionPolicy


@dataclass(frozen=True, slots=True)
class RedirectHop:
    """실제로 관측된 HTTP Redirect 한 단계."""

    source_url: str
    destination_url: str
    status_code: int
    location: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_url": self.source_url,
            "destination_url": self.destination_url,
            "status_code": self.status_code,
            "location": self.location,
        }


@dataclass(frozen=True, slots=True)
class PageSnapshot:
    """한 HTTP 수집 여정에서 확보한 응답과 부분 오류의 불변 기록."""

    snapshot_id: str
    collected_at: str
    original_url: str
    current_url: str
    final_url: str | None
    status_code: int | None
    response_headers: tuple[tuple[str, str], ...]
    body: bytes
    captured_body_sha256: str
    content_type: str | None
    encoding: str | None
    truncated: bool
    redirect_chain: tuple[RedirectHop, ...]
    collection_errors: tuple[CollectionError, ...]
    request_profile: CollectionPolicy

    @property
    def response_received(self) -> bool:
        """Redirect가 아닌 최종 HTTP 응답을 확보했는지 나타낸다."""
        return self.final_url is not None and self.status_code is not None

    def header(self, name: str) -> str | None:
        """대소문자를 구분하지 않고 첫 번째 응답 헤더 값을 반환한다."""
        normalized = name.casefold()
        for key, value in self.response_headers:
            if key.casefold() == normalized:
                return value
        return None

    def error_dicts(self) -> list[dict[str, Any]]:
        """계층별 결과 계약에서 사용할 오류 목록을 복사해 반환한다."""
        return [error.to_dict() for error in self.collection_errors]

    def metadata(self) -> dict[str, Any]:
        """민감할 수 있는 본문을 제외한 통합 결과용 추적 메타데이터."""
        return {
            "snapshot_id": self.snapshot_id,
            "collected_at": self.collected_at,
            "original_url": self.original_url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "redirect_chain": [hop.to_dict() for hop in self.redirect_chain],
            "captured_body_sha256": self.captured_body_sha256,
            "captured_body_size": len(self.body),
            "content_type": self.content_type,
            "encoding": self.encoding,
            "truncated": self.truncated,
            "request_profile": self.request_profile.to_dict(),
            "collection_errors": self.error_dicts(),
        }
