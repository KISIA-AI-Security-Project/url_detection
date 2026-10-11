"""독립 실행형 L3 URL 스캔을 위한 명령행 진입점."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .l3_scanner import scan_url
from .output import write_split_result
from .policies.operational import operational_detection_policy
from .policies.runtime import RuntimeConfig


def main() -> None:
    """URL 하나를 제한 수집·분석하고 구조화 결과를 JSON으로 출력한다."""
    parser = argparse.ArgumentParser(
        description="Collect and analyze one URL with the L3 scanner"
    )
    parser.add_argument("url", help="absolute HTTP(S) target URL")
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
    policy = operational_detection_policy(args.policy, args.wikidata_brand_cache)
    runtime = RuntimeConfig(fetch_external_scripts=args.fetch_external_scripts)
    result = scan_url(args.url, policy=policy, runtime=runtime)
    if args.output is None:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    raw_path, signals_path = write_split_result(args.output, result)
    print(f"L3 raw result saved to {raw_path}", file=sys.stderr)
    print(f"L3 signal result saved to {signals_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
