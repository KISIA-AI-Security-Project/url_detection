"""독립 실행형 L3 URL 스캔을 위한 명령행 진입점."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping

from .l3_scanner import scan_url
from .policies.experimental import experimental_detection_policy
from .policies.runtime import RuntimeConfig


_COMMON_OUTPUT_KEYS = ("schema_version", "layer", "target", "scan", "errors")


def _output_paths(output: Path) -> tuple[Path, Path]:
    """단일 출력 경로를 Raw/Signal JSON 경로로 확장한다."""
    suffix = output.suffix or ".json"
    stem = output.stem if output.suffix else output.name
    return (
        output.with_name(f"{stem}_raw{suffix}"),
        output.with_name(f"{stem}_signals{suffix}"),
    )


def _output_documents(
    result: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """공통 추적 메타데이터를 유지하며 Raw와 Signal 출력을 분리한다."""
    common = {key: result[key] for key in _COMMON_OUTPUT_KEYS if key in result}
    return (
        {**common, "raw": result.get("raw", {})},
        {**common, "signals": result.get("signals", [])},
    )


def _write_json(path: Path, document: Mapping[str, Any]) -> None:
    path.write_text(
        f"{json.dumps(document, ensure_ascii=False, indent=2)}\n",
        encoding="utf-8",
    )


def main() -> None:
    """URL 하나를 제한 수집·분석하고 구조화 결과를 JSON으로 출력한다."""
    parser = argparse.ArgumentParser(
        description="Collect and analyze one URL with the L3 scanner"
    )
    parser.add_argument("url", help="absolute HTTP(S) target URL")
    parser.add_argument(
        "--all",
        action="store_true",
        help=(
            "enable the experimental AWS smoke-test policy and bounded external "
            "JavaScript collection"
        ),
    )
    parser.add_argument(
        "--fetch-external-scripts",
        action="store_true",
        help="fetch external JavaScript with the configured resource limits",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help=(
            "write separate <name>_raw.json and <name>_signals.json files "
            "instead of stdout"
        ),
    )
    args = parser.parse_args()
    policy = experimental_detection_policy() if args.all else None
    runtime = RuntimeConfig(
        fetch_external_scripts=args.all or args.fetch_external_scripts
    )
    result = scan_url(args.url, policy=policy, runtime=runtime)
    if args.output is None:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    args.output.parent.mkdir(parents=True, exist_ok=True)
    raw_path, signals_path = _output_paths(args.output)
    raw_document, signals_document = _output_documents(result)
    _write_json(raw_path, raw_document)
    _write_json(signals_path, signals_document)
    print(f"L3 raw result saved to {raw_path}", file=sys.stderr)
    print(f"L3 signal result saved to {signals_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
