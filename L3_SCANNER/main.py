"""독립 실행형 L3 URL 스캔을 위한 명령행 진입점."""

from __future__ import annotations

import argparse
import json

from .l3_scanner import scan_url


def main() -> None:
    """URL 하나를 제한 수집·분석하고 구조화 결과를 JSON으로 출력한다."""
    parser = argparse.ArgumentParser(
        description="Collect and analyze one URL with the L3 scanner"
    )
    parser.add_argument("url", help="absolute HTTP(S) target URL")
    args = parser.parse_args()
    print(json.dumps(scan_url(args.url), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
