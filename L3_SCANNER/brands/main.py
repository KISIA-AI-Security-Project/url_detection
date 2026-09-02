"""Wikidata 브랜드 정책 캐시를 명시적으로 생성·갱신하는 CLI."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from L3_SCANNER.brands.cloudflare import (
    CloudflareRankingConfig,
    fetch_cloudflare_top_domains,
)
from L3_SCANNER.brands.wikidata import (
    WikidataSyncConfig,
    cached_requested_names,
    load_wikidata_brand_cache,
    sync_ranked_domains_to_wikidata_cache,
    sync_wikidata_brand_cache,
    write_wikidata_brand_cache,
)


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def _positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def _brand_file(path: Path) -> list[str]:
    """빈 줄과 주석을 제외한 UTF-8 브랜드 요청명을 읽는다."""
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _parser() -> argparse.ArgumentParser:
    defaults = WikidataSyncConfig()
    parser = argparse.ArgumentParser(
        description="Build a versioned local brand-policy cache from Wikidata"
    )
    parser.add_argument(
        "--brand",
        action="append",
        default=[],
        help="exact brand/entity label to resolve; may be repeated",
    )
    parser.add_argument(
        "--brand-file",
        action="append",
        type=Path,
        default=[],
        help="UTF-8 file containing one brand name per line",
    )
    parser.add_argument(
        "--refresh-cache",
        type=Path,
        help="reuse all requested names from an existing Wikidata cache",
    )
    parser.add_argument(
        "--cloudflare-top-domains",
        type=_positive_int,
        metavar="N",
        help="select the ordered global top N domains from Cloudflare Radar (max 100)",
    )
    parser.add_argument(
        "--cloudflare-token-env",
        default="CLOUDFLARE_API_TOKEN",
        help="environment variable containing the Cloudflare API token",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--language",
        action="append",
        help="Wikidata label language in priority order; defaults to ko then en",
    )
    parser.add_argument(
        "--request-timeout",
        type=_positive_float,
        default=defaults.request_timeout_seconds,
    )
    parser.add_argument(
        "--max-search-results",
        type=_positive_int,
        default=defaults.max_search_results,
    )
    parser.add_argument(
        "--max-response-bytes",
        type=_positive_int,
        default=defaults.max_response_bytes,
    )
    parser.add_argument("--max-brands", type=_positive_int, default=defaults.max_brands)
    parser.add_argument(
        "--user-agent",
        default=defaults.user_agent,
        help="descriptive User-Agent; production use should include contact information",
    )
    return parser


def main() -> None:
    """명시한 브랜드 집합을 조회하고 성공·미확정 항목을 함께 캐시에 기록한다."""
    parser = _parser()
    args = parser.parse_args()
    names = list(args.brand)
    for path in args.brand_file:
        names.extend(_brand_file(path))
    if args.refresh_cache is not None:
        names.extend(
            cached_requested_names(load_wikidata_brand_cache(args.refresh_cache))
        )
    if args.cloudflare_top_domains is not None and names:
        parser.error(
            "--cloudflare-top-domains cannot be combined with brand or refresh inputs"
        )
    if args.cloudflare_top_domains is None and not names:
        parser.error("at least one brand input or --cloudflare-top-domains is required")

    wikidata_config = WikidataSyncConfig(
        request_timeout_seconds=args.request_timeout,
        max_response_bytes=args.max_response_bytes,
        max_search_results=args.max_search_results,
        max_brands=args.max_brands,
        languages=tuple(args.language or ("ko", "en")),
        user_agent=args.user_agent,
    )
    selected_domain_count = 0
    if args.cloudflare_top_domains is not None:
        token = os.environ.get(args.cloudflare_token_env)
        if token is None or not token.strip():
            parser.error(
                f"environment variable {args.cloudflare_token_env!r} must contain "
                "a Cloudflare API token"
            )
        try:
            ranking_config = CloudflareRankingConfig(
                limit=args.cloudflare_top_domains,
                request_timeout_seconds=args.request_timeout,
                max_response_bytes=args.max_response_bytes,
                user_agent=args.user_agent,
            )
        except ValueError as exc:
            parser.error(str(exc))
        ranked_domains = fetch_cloudflare_top_domains(token, ranking_config)
        selected_domain_count = len(ranked_domains)
        cache = sync_ranked_domains_to_wikidata_cache(ranked_domains, wikidata_config)
    else:
        cache = sync_wikidata_brand_cache(names, wikidata_config)
    write_wikidata_brand_cache(args.output, cache)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "provider": cache.provider,
                "generated_at": cache.generated_at,
                "resolved": len(cache.brands),
                "unresolved": len(cache.unresolved),
                "selected_domains": selected_domain_count,
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
