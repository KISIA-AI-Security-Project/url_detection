"""악성 URL CSV/ZIP 데이터셋을 안전하게 선별하고 제한 스캔하는 어댑터.

데이터셋 행은 L3 Signal 판정 정책이 아니라 URL 입력 후보로만 사용한다. ZIP은 파일을
추출하지 않고 스트리밍하며, 실제 네트워크 수집은 호출자가 명시한 유한한 건수에만
수행한다.
"""

from __future__ import annotations

import csv
import io
import zipfile
from collections import Counter
from contextlib import ExitStack, contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterator, Mapping, Protocol, TextIO
from urllib.parse import urlsplit

from L3_SCANNER.output import write_json, write_split_result
from L3_SCANNER.utils.hashing import sha256_text

REQUIRED_COLUMNS = frozenset({"url", "sources", "source_status", "first_seen"})
ACTIVE_STATUS_TOKENS = frozenset({"active", "online", "yes"})
INACTIVE_STATUS_TOKENS = frozenset({"inactive", "offline"})


class URLScanner(Protocol):
    """배치 실행기가 요구하는 최소 Scanner 인터페이스."""

    def scan_url(self, url: str) -> dict[str, Any]: ...


@dataclass(frozen=True, slots=True)
class DatasetConfig:
    """데이터셋 입력 자체에 적용하는 명시적 자원 제한."""

    max_uncompressed_bytes: int = 256 * 1024 * 1024

    def __post_init__(self) -> None:
        if self.max_uncompressed_bytes <= 0:
            raise ValueError("max_uncompressed_bytes must be positive")


@dataclass(frozen=True, slots=True)
class DatasetRecord:
    """원본 행 번호와 Feed 메타데이터를 보존한 URL 입력 후보."""

    row_number: int
    url: str
    sources: str
    source_status: str
    first_seen: str

    @property
    def active(self) -> bool:
        """Feed별 복합 상태에서 비활성 표시를 우선해 활성 여부를 계산한다."""
        tokens = {
            token.strip().casefold()
            for token in self.source_status.split("|")
            if token.strip()
        }
        return bool(tokens & ACTIVE_STATUS_TOKENS) and not bool(
            tokens & INACTIVE_STATUS_TOKENS
        )

    @property
    def rejection_reason(self) -> str | None:
        """네트워크 접근 없이 Collector가 받을 수 없는 URL 형식을 분류한다."""
        try:
            parts = urlsplit(self.url)
            if parts.scheme.casefold() not in {"http", "https"}:
                return "unsupported_scheme"
            if not parts.hostname:
                return "missing_hostname"
            if parts.username is not None or parts.password is not None:
                return "userinfo_not_allowed"
            # 잘못된 포트 표현은 ``parts.port`` 접근 시 ValueError가 발생한다.
            _ = parts.port
        except ValueError:
            return "malformed_url"
        return None


@dataclass(frozen=True, slots=True)
class DatasetSummary:
    """DNS 조회나 HTTP 요청 없이 계산한 데이터셋 사전 검사 결과."""

    total_rows: int
    active_rows: int
    eligible_rows: int
    active_eligible_rows: int
    rejected: Mapping[str, int]
    sources: Mapping[str, int]
    source_statuses: Mapping[str, int]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class DatasetScanConfig:
    """실제 URL 수집 범위를 명시적으로 제한하는 배치 설정."""

    limit: int
    offset: int = 0
    active_only: bool = True

    def __post_init__(self) -> None:
        if self.limit <= 0:
            raise ValueError("limit must be positive")
        if self.offset < 0:
            raise ValueError("offset must not be negative")


@contextmanager
def _open_dataset_csv(path: Path, config: DatasetConfig) -> Iterator[TextIO]:
    """CSV 또는 단일 CSV가 든 ZIP을 추출 없이 UTF-8 스트림으로 연다."""
    with ExitStack() as stack:
        if path.suffix.casefold() == ".zip":
            archive = stack.enter_context(zipfile.ZipFile(path))
            members = [
                info
                for info in archive.infolist()
                if not info.is_dir() and Path(info.filename).suffix.casefold() == ".csv"
            ]
            if len(members) != 1:
                raise ValueError("dataset ZIP must contain exactly one CSV file")
            member = members[0]
            if member.file_size > config.max_uncompressed_bytes:
                raise ValueError("dataset CSV exceeds max_uncompressed_bytes")
            binary = stack.enter_context(archive.open(member))
        else:
            if path.suffix.casefold() != ".csv":
                raise ValueError(
                    "dataset must be a CSV file or a ZIP containing one CSV"
                )
            if path.stat().st_size > config.max_uncompressed_bytes:
                raise ValueError("dataset CSV exceeds max_uncompressed_bytes")
            binary = stack.enter_context(path.open("rb"))

        text = stack.enter_context(
            io.TextIOWrapper(binary, encoding="utf-8-sig", errors="replace", newline="")
        )
        yield text


def iter_dataset_records(
    path: Path, config: DatasetConfig | None = None
) -> Iterator[DatasetRecord]:
    """필수 Header를 검증하고 데이터셋 행을 메모리에 누적하지 않고 순회한다."""
    active_config = config or DatasetConfig()
    with _open_dataset_csv(path, active_config) as stream:
        reader = csv.DictReader(stream)
        columns = set(reader.fieldnames or [])
        missing = sorted(REQUIRED_COLUMNS - columns)
        if missing:
            raise ValueError(f"dataset CSV is missing required columns: {missing}")
        for row_number, row in enumerate(reader, start=2):
            yield DatasetRecord(
                row_number=row_number,
                url=str(row.get("url") or "").strip(),
                sources=str(row.get("sources") or "").strip(),
                source_status=str(row.get("source_status") or "").strip(),
                first_seen=str(row.get("first_seen") or "").strip(),
            )


def summarize_dataset(
    path: Path, config: DatasetConfig | None = None
) -> DatasetSummary:
    """실제 접속 없이 전체 행의 상태와 L3 입력 적합도를 집계한다."""
    total_rows = 0
    active_rows = 0
    eligible_rows = 0
    active_eligible_rows = 0
    rejected: Counter[str] = Counter()
    sources: Counter[str] = Counter()
    statuses: Counter[str] = Counter()
    for record in iter_dataset_records(path, config):
        total_rows += 1
        active_rows += int(record.active)
        sources[record.sources] += 1
        statuses[record.source_status] += 1
        reason = record.rejection_reason
        if reason is not None:
            rejected[reason] += 1
            continue
        eligible_rows += 1
        active_eligible_rows += int(record.active)
    return DatasetSummary(
        total_rows=total_rows,
        active_rows=active_rows,
        eligible_rows=eligible_rows,
        active_eligible_rows=active_eligible_rows,
        rejected=dict(sorted(rejected.items())),
        sources=dict(sorted(sources.items())),
        source_statuses=dict(sorted(statuses.items())),
    )


def iter_scan_candidates(
    path: Path,
    scan: DatasetScanConfig,
    dataset: DatasetConfig | None = None,
) -> Iterator[DatasetRecord]:
    """활성·URL 형식 필터와 offset/limit을 적용한 유한 후보 목록을 만든다."""
    eligible_index = 0
    yielded = 0
    for record in iter_dataset_records(path, dataset):
        if record.rejection_reason is not None:
            continue
        if scan.active_only and not record.active:
            continue
        if eligible_index < scan.offset:
            eligible_index += 1
            continue
        yield record
        yielded += 1
        if yielded >= scan.limit:
            return


def scan_dataset(
    path: Path,
    output_dir: Path,
    scanner: URLScanner,
    scan: DatasetScanConfig,
    dataset: DatasetConfig | None = None,
) -> dict[str, Any]:
    """선별된 URL만 순차 수집하고 URL별 분리 결과와 매니페스트를 기록한다."""
    output_dir.mkdir(parents=True, exist_ok=True)
    items: list[dict[str, Any]] = []
    for record in iter_scan_candidates(path, scan, dataset):
        item: dict[str, Any] = {
            "row_number": record.row_number,
            "url": record.url,
            "sources": record.sources,
            "source_status": record.source_status,
            "first_seen": record.first_seen,
        }
        try:
            result = scanner.scan_url(record.url)
            base_name = f"row-{record.row_number}-{sha256_text(record.url)[:16]}.json"
            raw_path, signals_path = write_split_result(output_dir / base_name, result)
            item.update(
                status="completed",
                scan_status=result.get("scan", {}).get("status"),
                raw_file=raw_path.name,
                signals_file=signals_path.name,
                error=None,
            )
        except Exception as exc:
            # 데이터셋 한 행의 예상 밖 실패가 다음 URL 수집을 중단하지 않게 한다.
            item.update(
                status="error",
                scan_status=None,
                raw_file=None,
                signals_file=None,
                error={"exception": type(exc).__name__, "message": str(exc)},
            )
        items.append(item)

    manifest: dict[str, Any] = {
        "schema_version": "1.0",
        "layer": "L3",
        "dataset": str(path),
        "selection": asdict(scan),
        "processed": len(items),
        "items": items,
    }
    write_json(output_dir / "manifest.json", manifest)
    return manifest


__all__ = [
    "ACTIVE_STATUS_TOKENS",
    "DatasetConfig",
    "DatasetRecord",
    "DatasetScanConfig",
    "DatasetSummary",
    "INACTIVE_STATUS_TOKENS",
    "REQUIRED_COLUMNS",
    "URLScanner",
    "iter_dataset_records",
    "iter_scan_candidates",
    "scan_dataset",
    "summarize_dataset",
]
