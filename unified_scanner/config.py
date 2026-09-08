"""L2/L3 통합 실행에 사용하는 명시적인 수집·분석 설정."""

from __future__ import annotations

from dataclasses import dataclass, field

from l2_scanner.config.tuning import (
    HTTP_TIMEOUT_SECONDS,
    MAX_BODY_BYTES,
    MAX_REDIRECT_HOPS,
    USER_AGENT,
)
from url_collector import CollectionPolicy

from L3_SCANNER.policies.runtime import RuntimeConfig


def _default_collection_policy() -> CollectionPolicy:
    l3_defaults = RuntimeConfig()
    return CollectionPolicy(
        request_timeout_seconds=max(
            HTTP_TIMEOUT_SECONDS, l3_defaults.request_timeout_seconds
        ),
        max_redirects=max(MAX_REDIRECT_HOPS, l3_defaults.max_redirects),
        max_body_bytes=max(MAX_BODY_BYTES, l3_defaults.max_html_bytes),
        user_agent=USER_AGENT,
    )


@dataclass(frozen=True, slots=True)
class UnifiedConfig:
    """공통 페이지 수집과 L3 후속 분석에 적용할 런타임 설정."""

    collection: CollectionPolicy = field(default_factory=_default_collection_policy)
    l3_runtime: RuntimeConfig = field(default_factory=RuntimeConfig)
