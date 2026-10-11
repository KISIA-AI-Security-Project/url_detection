from __future__ import annotations

import csv
import json
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest

import L3_SCANNER.dataset_main as dataset_main_module
from L3_SCANNER.dataset import (
    DatasetConfig,
    DatasetScanConfig,
    iter_dataset_records,
    iter_scan_candidates,
    scan_dataset,
    summarize_dataset,
)


ROWS = [
    {
        "url": "https://active.example/login",
        "sources": "feed-a",
        "source_status": "ACTIVE",
        "first_seen": "2026-08-28T00:00:00Z",
    },
    {
        "url": "https://inactive.example/",
        "sources": "feed-a",
        "source_status": "INACTIVE|yes",
        "first_seen": "2026-08-28T00:00:00Z",
    },
    {
        "url": "ftp://unsupported.example/file",
        "sources": "feed-b",
        "source_status": "online",
        "first_seen": "2026-08-28T00:00:00Z",
    },
    {
        "url": "https://user:secret@example.net/",
        "sources": "feed-b",
        "source_status": "yes",
        "first_seen": "2026-08-28T00:00:00Z",
    },
    {
        "url": "http://online.example/path",
        "sources": "feed-c",
        "source_status": "online",
        "first_seen": "2026-08-29T00:00:00Z",
    },
]


def _zip_dataset(path: Path, rows: list[dict[str, str]] = ROWS) -> Path:
    csv_path = path.with_suffix(".csv")
    with csv_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(ROWS[0]))
        writer.writeheader()
        writer.writerows(rows)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(csv_path, "dataset.csv")
    return path


def test_dataset_zip_is_streamed_and_summarized_without_network(tmp_path: Path) -> None:
    dataset = _zip_dataset(tmp_path / "dataset.zip")

    records = list(iter_dataset_records(dataset))
    summary = summarize_dataset(dataset)

    assert len(records) == 5
    assert records[0].row_number == 2
    assert records[0].active is True
    assert records[1].active is False
    assert summary.total_rows == 5
    assert summary.active_rows == 4
    assert summary.eligible_rows == 3
    assert summary.active_eligible_rows == 2
    assert summary.rejected == {
        "unsupported_scheme": 1,
        "userinfo_not_allowed": 1,
    }


def test_scan_candidates_apply_active_filter_offset_and_limit(tmp_path: Path) -> None:
    dataset = _zip_dataset(tmp_path / "dataset.zip")

    selected = list(
        iter_scan_candidates(
            dataset,
            DatasetScanConfig(limit=1, offset=1, active_only=True),
        )
    )

    assert [record.url for record in selected] == ["http://online.example/path"]


def test_dataset_size_and_required_columns_are_validated(tmp_path: Path) -> None:
    dataset = _zip_dataset(tmp_path / "dataset.zip")
    with pytest.raises(ValueError, match="max_uncompressed_bytes"):
        list(iter_dataset_records(dataset, DatasetConfig(max_uncompressed_bytes=10)))

    missing = tmp_path / "missing.csv"
    missing.write_text("url\nhttps://example.com\n", encoding="utf-8")
    with pytest.raises(ValueError, match="missing required columns"):
        list(iter_dataset_records(missing))


def test_scan_dataset_writes_split_results_and_manifest(tmp_path: Path) -> None:
    dataset = _zip_dataset(tmp_path / "dataset.zip")
    observed: list[str] = []

    class FakeScanner:
        def scan_url(self, url: str) -> dict[str, Any]:
            observed.append(url)
            return {
                "schema_version": "1.0",
                "layer": "L3",
                "target": {"original_url": url, "document_url": url},
                "scan": {"status": "completed"},
                "raw": {"html": {}, "javascript": {}},
                "signals": [{"id": "L3-H-01", "detected": False}],
                "errors": [],
            }

    output = tmp_path / "results"
    manifest = scan_dataset(
        dataset,
        output,
        FakeScanner(),
        DatasetScanConfig(limit=1),
    )

    assert observed == ["https://active.example/login"]
    assert manifest["processed"] == 1
    item = manifest["items"][0]
    raw = json.loads((output / item["raw_file"]).read_text(encoding="utf-8"))
    signals = json.loads((output / item["signals_file"]).read_text(encoding="utf-8"))
    saved_manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert "raw" in raw and "signals" not in raw
    assert "signals" in signals and "raw" not in signals
    assert saved_manifest["items"][0]["url"] == observed[0]


def test_dataset_cli_requires_explicit_live_limit_and_output(
    monkeypatch: Any, tmp_path: Path
) -> None:
    dataset = _zip_dataset(tmp_path / "dataset.zip")
    monkeypatch.setattr(
        sys,
        "argv",
        ["L3_SCANNER.dataset_main", str(dataset), "--scan"],
    )

    with pytest.raises(SystemExit, match="2"):
        dataset_main_module.main()
