"""URL Feed 데이터셋 사전 검사와 명시적 제한 배치 스캔 CLI."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from L3_SCANNER.dataset import (
    DatasetConfig,
    DatasetScanConfig,
    scan_dataset,
    summarize_dataset,
)
from L3_SCANNER.l3_scanner import L3Scanner
from L3_SCANNER.policies.operational import operational_detection_policy
from L3_SCANNER.policies.runtime import RuntimeConfig


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def _nonnegative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be a non-negative integer")
    return parsed


def _positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def _parser() -> argparse.ArgumentParser:
    defaults = RuntimeConfig()
    parser = argparse.ArgumentParser(
        description=(
            "Preflight a URL-feed CSV/ZIP or scan an explicitly bounded selection"
        )
    )
    parser.add_argument("dataset", type=Path, help="CSV or ZIP containing one CSV")
    parser.add_argument(
        "--scan",
        action="store_true",
        help="perform live HTTP(S) collection; without this flag only preflight runs",
    )
    parser.add_argument(
        "--limit",
        type=_positive_int,
        help="required maximum number of live URL scans",
    )
    parser.add_argument("--offset", type=_nonnegative_int, default=0)
    parser.add_argument(
        "--include-inactive",
        action="store_true",
        help="include inactive or unknown-status rows in the bounded selection",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="required directory for split results and manifest in live scan mode",
    )
    parser.add_argument(
        "--policy",
        type=Path,
        help="operational policy JSON; defaults to the bundled operational-v1 policy",
    )
    parser.add_argument(
        "--wikidata-brand-cache",
        type=Path,
        help="versioned Wikidata-only brand policy cache for L3-H-05/L3-H-06",
    )
    parser.add_argument(
        "--fetch-external-scripts",
        action="store_true",
        help="fetch external JavaScript under the configured resource limits",
    )
    parser.add_argument(
        "--max-dataset-bytes",
        type=_positive_int,
        default=DatasetConfig().max_uncompressed_bytes,
    )
    parser.add_argument(
        "--request-timeout",
        type=_positive_float,
        default=defaults.request_timeout_seconds,
    )
    parser.add_argument(
        "--max-redirects", type=_nonnegative_int, default=defaults.max_redirects
    )
    parser.add_argument(
        "--max-html-bytes", type=_positive_int, default=defaults.max_html_bytes
    )
    parser.add_argument(
        "--max-script-bytes", type=_positive_int, default=defaults.max_script_bytes
    )
    parser.add_argument(
        "--max-external-scripts",
        type=_nonnegative_int,
        default=defaults.max_external_scripts,
    )
    parser.add_argument(
        "--max-javascript-events",
        type=_positive_int,
        default=defaults.max_javascript_events,
    )
    return parser


def main() -> None:
    """기본은 비접속 사전 검사이며 ``--scan``일 때만 제한 수집을 수행한다."""
    parser = _parser()
    args = parser.parse_args()
    dataset_config = DatasetConfig(max_uncompressed_bytes=args.max_dataset_bytes)
    if not args.scan:
        if args.limit is not None or args.output_dir is not None:
            parser.error("--limit and --output-dir require --scan")
        summary = summarize_dataset(args.dataset, dataset_config)
        print(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2))
        return

    if args.limit is None:
        parser.error("--scan requires --limit")
    if args.output_dir is None:
        parser.error("--scan requires --output-dir")
    runtime = RuntimeConfig(
        request_timeout_seconds=args.request_timeout,
        max_redirects=args.max_redirects,
        max_html_bytes=args.max_html_bytes,
        max_script_bytes=args.max_script_bytes,
        max_external_scripts=args.max_external_scripts,
        fetch_external_scripts=args.fetch_external_scripts,
        max_javascript_events=args.max_javascript_events,
    )
    scanner = L3Scanner(
        operational_detection_policy(args.policy, args.wikidata_brand_cache), runtime
    )
    manifest = scan_dataset(
        args.dataset,
        args.output_dir,
        scanner,
        DatasetScanConfig(
            limit=args.limit,
            offset=args.offset,
            active_only=not args.include_inactive,
        ),
        dataset_config,
    )
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
