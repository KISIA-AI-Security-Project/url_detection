"""한 HTTP 페이지 스냅샷을 L2와 L3에 함께 전달하는 오케스트레이터."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import nullcontext
from typing import Any, Protocol
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from time import perf_counter
from L3_SCANNER.policies.operational import operational_detection_policy

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
        timing_observer: Callable | None = None,
    ) -> None:
        self.config = config or UnifiedConfig()
        self._collector = collector
        self._l2_runner = l2_runner
        self._timing = timing_observer or (lambda _name: nullcontext())
        self._l3_runner = l3_runner or L3Scanner(
            detection_policy if detection_policy is not None else operational_detection_policy(), self.config.l3_runtime
        )

    def scan_url(self, url: str, *, budget_seconds: float | None = None) -> dict[str, Any]:
        """페이지를 정확히 한 번 수집하고 L2/L3 결과를 독립적으로 조립한다."""
        if budget_seconds is not None and budget_seconds <= 0:
            raise ValueError('budget_seconds must be positive')
        deadline = None if budget_seconds is None else perf_counter() + budget_seconds
        def remaining():
            return None if deadline is None else max(0.0, deadline - perf_counter())
        pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix='shared-l23')
        def collect():
            with self._timing('collection.http'):
                return self._collector(url, self.config.collection)
        try:
            snapshot = pool.submit(collect).result(timeout=remaining())
        except BaseException:
            pool.shutdown(wait=False, cancel_futures=True)
            raise
        errors: list[LayerError] = []

        timings = {}
        def timed(name, runner):
            started = perf_counter()
            try:
                with self._timing('analysis.' + name.lower()):
                    return runner(snapshot)
            finally: timings[name] = perf_counter() - started
        try:
            futures = {"L2":pool.submit(timed,"L2",self._l2_runner),
                       "L3":pool.submit(timed,"L3",self._l3_runner.scan_snapshot)}
            results = {}
            for name, future in futures.items():
                try: results[name] = future.result(timeout=remaining())
                except Exception as exc:
                    results[name] = None
                    timed_out = isinstance(exc, FutureTimeout) and not future.done()
                    errors.append(LayerError(name,'LayerBudgetExceeded' if timed_out else type(exc).__name__,str(exc)))
            l2_result, l3_result = results["L2"], results["L3"]
        finally:
            # Same bounded wait as the deployed L23 adapter. Running workers may
            # finish later, but cannot publish records or start another page scan.
            pool.shutdown(wait=False, cancel_futures=True)
        for name, result in [("L2",l2_result),("L3",l3_result)]:
            if result is not None: result.setdefault("scan",{})["analysis_elapsed_seconds"] = timings.get(name)

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
