"""L3 결과를 Raw/Signal JSON 문서로 분리해 저장하는 공통 도우미."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

COMMON_OUTPUT_KEYS = ("schema_version", "layer", "target", "scan", "errors")


def output_paths(output: Path) -> tuple[Path, Path]:
    """단일 기본 경로를 Raw/Signal JSON 경로로 확장한다."""
    suffix = output.suffix or ".json"
    stem = output.stem if output.suffix else output.name
    return (
        output.with_name(f"{stem}_raw{suffix}"),
        output.with_name(f"{stem}_signals{suffix}"),
    )


def output_documents(
    result: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """공통 추적 메타데이터를 유지하며 Raw와 Signal 출력을 분리한다."""
    common = {key: result[key] for key in COMMON_OUTPUT_KEYS if key in result}
    return (
        {**common, "raw": result.get("raw", {})},
        {**common, "signals": result.get("signals", [])},
    )


def write_json(path: Path, document: Mapping[str, Any]) -> None:
    """상위 경로를 준비하고 UTF-8 JSON 문서를 기록한다."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"{json.dumps(document, ensure_ascii=False, indent=2)}\n",
        encoding="utf-8",
    )


def write_split_result(output: Path, result: Mapping[str, Any]) -> tuple[Path, Path]:
    """L3 Result 하나를 Raw/Signal 파일로 기록하고 두 경로를 반환한다."""
    raw_path, signals_path = output_paths(output)
    raw_document, signals_document = output_documents(result)
    write_json(raw_path, raw_document)
    write_json(signals_path, signals_document)
    return raw_path, signals_path


__all__ = [
    "COMMON_OUTPUT_KEYS",
    "output_documents",
    "output_paths",
    "write_json",
    "write_split_result",
]
