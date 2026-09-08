"""한 HTTP 페이지 스냅샷을 L2와 L3에 함께 전달하는 오케스트레이터."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol

from l2_scanner import scan_snapshot as scan_l2_snapshot
from url_collector import CollectionPolicy, PageSnapshot, collect_url

from L3_SCANNER import L3Scanner
from L3_SCANNER.policies.detection import DetectionPolicy

from .config import UnifiedConfig
from .models import LayerError, UnifiedScanResult

Collector = Callable[[str, CollectionPolicy], PageSnapshot]
LayerRunner = Callable[[PageSnapshot], dict[str, Any]]


class L3SnapshotRunner(Protocol):
    def scan_snapshot(self, snapshot: PageSnapshot) -> dict[str, Any]: ...


class UnifiedScanner:
    """단일 수집을 강제하고 같은 불변 Snapshot으로 두 계층을 실행한다."""

    def __init__(
        self,
        config: UnifiedConfig | None = None,
        detection_policy: DetectionPolicy | None = None,
        *,
        collector: Collector = collect_url,
        l2_runner: LayerRunner = scan_l2_snapshot,
        l3_runner: L3SnapshotRunner | None = None,
    ) -> None:
        self.config = config or UnifiedConfig()
        self._collector = collector
        self._l2_runner = l2_runner
        self._l3_runner = l3_runner or L3Scanner(
            detection_policy, self.config.l3_runtime
        )

    def scan_url(self, url: str) -> dict[str, Any]:
        """페이지를 정확히 한 번 수집하고 L2/L3 결과를 독립적으로 조립한다."""
        snapshot = self._collector(url, self.config.collection)
        errors: list[LayerError] = []

        try:
            l2_result = self._l2_runner(snapshot)
        except Exception as exc:
            l2_result = None
            errors.append(LayerError("L2", type(exc).__name__, str(exc)))

        try:
            l3_result = self._l3_runner.scan_snapshot(snapshot)
        except Exception as exc:
            l3_result = None
            errors.append(LayerError("L3", type(exc).__name__, str(exc)))

        return UnifiedScanResult(
            snapshot=snapshot,
            l2=l2_result,
            l3=l3_result,
            errors=tuple(errors),
        ).to_dict()


def scan_url(
    url: str,
    config: UnifiedConfig | None = None,
    detection_policy: DetectionPolicy | None = None,
) -> dict[str, Any]:
    """일회성 통합 URL 분석을 위한 편의 함수."""
    return UnifiedScanner(config, detection_policy).scan_url(url)
