"""Signal 탐지 정책과 분리된 공통 HTTP 수집 제한."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CollectionPolicy:
    """단일 HTTP 수집 여정에 적용할 명시적인 자원 제한과 요청 프로필."""

    request_timeout_seconds: float
    max_redirects: int
    max_body_bytes: int
    user_agent: str

    def __post_init__(self) -> None:
        if self.request_timeout_seconds <= 0:
            raise ValueError("request_timeout_seconds must be positive")
        if self.max_redirects < 0:
            raise ValueError("max_redirects must be non-negative")
        if self.max_body_bytes < 0:
            raise ValueError("max_body_bytes must be non-negative")
        if not self.user_agent.strip():
            raise ValueError("user_agent must not be empty")

    def to_dict(self) -> dict[str, object]:
        """스냅샷 추적 메타데이터에 사용할 직렬화 표현을 반환한다."""
        return {
            "request_timeout_seconds": self.request_timeout_seconds,
            "max_redirects": self.max_redirects,
            "max_body_bytes": self.max_body_bytes,
            "user_agent": self.user_agent,
        }
