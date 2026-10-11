"""Wikidata를 단일 원천으로 사용하는 버전형 브랜드 정책 캐시.

Scanner/Analyzer는 이 모듈을 통해 네트워크를 호출하지 않는다. 명시적인 동기화
명령만 Wikidata API를 호출하며, 실제 분석에는 검증된 로컬 캐시만 주입한다.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, Iterable, Mapping

import httpx

from L3_SCANNER.brands.cloudflare import RankedDomain
from L3_SCANNER.utils.url import etld1, registrable_domain_label

WIKIDATA_API_URL = "https://www.wikidata.org/w/api.php"
WIKIDATA_CACHE_SCHEMA_VERSION = "1.0"
WIKIDATA_PROVIDER_NAME = "wikidata"


class WikidataPolicyError(ValueError):
    """Wikidata 응답 또는 브랜드 캐시가 지원 계약을 위반했음을 나타낸다."""


@dataclass(frozen=True, slots=True)
class WikidataSyncConfig:
    """Wikidata 브랜드 정책 동기화의 명시적 네트워크 제한."""

    api_url: str = WIKIDATA_API_URL
    request_timeout_seconds: float = 10.0
    max_response_bytes: int = 2_000_000
    max_search_results: int = 10
    max_brands: int = 500
    languages: tuple[str, ...] = ("ko", "en")
    user_agent: str = "L3-Scanner/0.1 (Wikidata brand policy sync)"

    def __post_init__(self) -> None:
        if self.api_url != WIKIDATA_API_URL:
            raise WikidataPolicyError("only the official Wikidata API is supported")
        if self.request_timeout_seconds <= 0:
            raise WikidataPolicyError("request_timeout_seconds must be positive")
        if self.max_response_bytes <= 0:
            raise WikidataPolicyError("max_response_bytes must be positive")
        if self.max_search_results <= 0:
            raise WikidataPolicyError("max_search_results must be positive")
        if self.max_brands <= 0:
            raise WikidataPolicyError("max_brands must be positive")
        if not self.languages or any(not value.strip() for value in self.languages):
            raise WikidataPolicyError("languages must contain non-empty values")
        if not self.user_agent.strip():
            raise WikidataPolicyError("user_agent must not be empty")


@dataclass(frozen=True, slots=True)
class WikidataBrandEntry:
    """한 Wikidata Item에서 검증한 브랜드 식별자와 현재 공식 도메인."""

    requested_name: str
    entity_id: str
    revision_id: int | None
    label: str
    aliases: tuple[str, ...]
    expected_domains: tuple[str, ...]
    selection_domain: str | None = None
    selection_rank: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "requested_name": self.requested_name,
            "entity_id": self.entity_id,
            "revision_id": self.revision_id,
            "label": self.label,
            "aliases": list(self.aliases),
            "expected_domains": list(self.expected_domains),
            "selection_domain": self.selection_domain,
            "selection_rank": self.selection_rank,
        }


@dataclass(frozen=True, slots=True)
class WikidataUnresolvedEntry:
    """자동 확정하지 못해 Analyzer 정책에 포함하지 않은 브랜드 요청."""

    requested_name: str
    reason: str
    candidate_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "requested_name": self.requested_name,
            "reason": self.reason,
            "candidate_ids": list(self.candidate_ids),
        }


@dataclass(frozen=True, slots=True)
class WikidataSelection:
    """브랜드 후보를 고른 외부 Ranking의 비정책성 출처."""

    provider: str
    dataset: str
    requested_limit: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "dataset": self.dataset,
            "requested_limit": self.requested_limit,
        }


@dataclass(frozen=True, slots=True)
class WikidataBrandCache:
    """분석 시 네트워크 없이 읽는 Wikidata 브랜드 정책 스냅샷."""

    generated_at: str
    brands: tuple[WikidataBrandEntry, ...]
    unresolved: tuple[WikidataUnresolvedEntry, ...] = ()
    selection: WikidataSelection | None = None
    schema_version: str = WIKIDATA_CACHE_SCHEMA_VERSION
    provider: str = WIKIDATA_PROVIDER_NAME

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "provider": self.provider,
            "generated_at": self.generated_at,
            "brands": [entry.to_dict() for entry in self.brands],
            "unresolved": [entry.to_dict() for entry in self.unresolved],
            "selection": self.selection.to_dict()
            if self.selection is not None
            else None,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "WikidataBrandCache":
        _reject_unknown(
            value,
            {
                "schema_version",
                "provider",
                "generated_at",
                "brands",
                "unresolved",
                "selection",
            },
            "cache",
        )
        schema_version = _string(value.get("schema_version"), "cache.schema_version")
        if schema_version != WIKIDATA_CACHE_SCHEMA_VERSION:
            raise WikidataPolicyError(
                f"unsupported Wikidata cache schema_version: {schema_version}"
            )
        provider = _string(value.get("provider"), "cache.provider")
        if provider != WIKIDATA_PROVIDER_NAME:
            raise WikidataPolicyError("brand cache provider must be wikidata")
        generated_at = _string(value.get("generated_at"), "cache.generated_at")
        brands_value = _list(value.get("brands"), "cache.brands")
        unresolved_value = _list(value.get("unresolved"), "cache.unresolved")
        brands = tuple(
            _brand_entry(item, f"cache.brands[{index}]")
            for index, item in enumerate(brands_value)
        )
        unresolved = tuple(
            _unresolved_entry(item, f"cache.unresolved[{index}]")
            for index, item in enumerate(unresolved_value)
        )
        selection_value = value.get("selection")
        selection = (
            _selection(selection_value, "cache.selection")
            if selection_value is not None
            else None
        )
        entity_ids = [entry.entity_id for entry in brands]
        if len(entity_ids) != len(set(entity_ids)):
            raise WikidataPolicyError(
                "cache.brands contains duplicate entity_id values"
            )
        labels = [entry.label.casefold() for entry in brands]
        if len(labels) != len(set(labels)):
            raise WikidataPolicyError(
                "cache.brands contains ambiguous duplicate labels"
            )
        return cls(
            schema_version=schema_version,
            provider=provider,
            generated_at=generated_at,
            brands=brands,
            unresolved=unresolved,
            selection=selection,
        )


def _reject_unknown(value: Mapping[str, Any], allowed: set[str], path: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise WikidataPolicyError(f"unknown fields at {path}: {unknown}")


def _string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise WikidataPolicyError(f"{path} must be a non-empty string")
    return value.strip()


def _list(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise WikidataPolicyError(f"{path} must be an array")
    return value


def _mapping(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise WikidataPolicyError(f"{path} must be an object")
    return value


def _string_list(value: Any, path: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    items = _list(value, path)
    if not items and not allow_empty:
        raise WikidataPolicyError(f"{path} must not be empty")
    result: list[str] = []
    for index, item in enumerate(items):
        normalized = _string(item, f"{path}[{index}]")
        if normalized not in result:
            result.append(normalized)
    return tuple(result)


def _entity_id(value: Any, path: str) -> str:
    entity_id = _string(value, path)
    if re.fullmatch(r"Q[1-9][0-9]*", entity_id) is None:
        raise WikidataPolicyError(f"{path} must be a Wikidata item ID")
    return entity_id


def _brand_entry(value: Any, path: str) -> WikidataBrandEntry:
    item = _mapping(value, path)
    _reject_unknown(
        item,
        {
            "requested_name",
            "entity_id",
            "revision_id",
            "label",
            "aliases",
            "expected_domains",
            "selection_domain",
            "selection_rank",
        },
        path,
    )
    revision_id = item.get("revision_id")
    if revision_id is not None and (
        not isinstance(revision_id, int)
        or isinstance(revision_id, bool)
        or revision_id <= 0
    ):
        raise WikidataPolicyError(
            f"{path}.revision_id must be a positive integer or null"
        )
    domains = _string_list(
        item.get("expected_domains"), f"{path}.expected_domains", allow_empty=False
    )
    normalized_domains: list[str] = []
    for domain in domains:
        normalized = etld1(f"https://{domain.lower().rstrip('.')}")
        if normalized is None:
            raise WikidataPolicyError(
                f"{path}.expected_domains contains an invalid domain: {domain}"
            )
        if normalized not in normalized_domains:
            normalized_domains.append(normalized)
    selection_domain_value = item.get("selection_domain")
    selection_domain = None
    if selection_domain_value is not None:
        raw_selection_domain = _string(
            selection_domain_value, f"{path}.selection_domain"
        )
        selection_domain = etld1(f"https://{raw_selection_domain}")
        if selection_domain is None or selection_domain not in normalized_domains:
            raise WikidataPolicyError(
                f"{path}.selection_domain must match an expected domain"
            )
    selection_rank = item.get("selection_rank")
    if selection_rank is not None and (
        not isinstance(selection_rank, int)
        or isinstance(selection_rank, bool)
        or selection_rank <= 0
    ):
        raise WikidataPolicyError(f"{path}.selection_rank must be positive or null")
    if (selection_domain is None) != (selection_rank is None):
        raise WikidataPolicyError(
            f"{path}.selection_domain and selection_rank must be set together"
        )
    return WikidataBrandEntry(
        requested_name=_string(item.get("requested_name"), f"{path}.requested_name"),
        entity_id=_entity_id(item.get("entity_id"), f"{path}.entity_id"),
        revision_id=revision_id,
        label=_string(item.get("label"), f"{path}.label"),
        aliases=_string_list(item.get("aliases"), f"{path}.aliases"),
        expected_domains=tuple(normalized_domains),
        selection_domain=selection_domain,
        selection_rank=selection_rank,
    )


def _unresolved_entry(value: Any, path: str) -> WikidataUnresolvedEntry:
    item = _mapping(value, path)
    _reject_unknown(item, {"requested_name", "reason", "candidate_ids"}, path)
    return WikidataUnresolvedEntry(
        requested_name=_string(item.get("requested_name"), f"{path}.requested_name"),
        reason=_string(item.get("reason"), f"{path}.reason"),
        candidate_ids=tuple(
            _entity_id(candidate, f"{path}.candidate_ids[{index}]")
            for index, candidate in enumerate(
                _list(item.get("candidate_ids"), f"{path}.candidate_ids")
            )
        ),
    )


def _selection(value: Any, path: str) -> WikidataSelection:
    item = _mapping(value, path)
    _reject_unknown(item, {"provider", "dataset", "requested_limit"}, path)
    provider = _string(item.get("provider"), f"{path}.provider")
    if provider != "cloudflare_radar":
        raise WikidataPolicyError(f"{path}.provider must be cloudflare_radar")
    dataset = _string(item.get("dataset"), f"{path}.dataset")
    if dataset != "domain_ranking_top":
        raise WikidataPolicyError(f"{path}.dataset must be domain_ranking_top")
    requested_limit = item.get("requested_limit")
    if (
        not isinstance(requested_limit, int)
        or isinstance(requested_limit, bool)
        or not 1 <= requested_limit <= 100
    ):
        raise WikidataPolicyError(f"{path}.requested_limit must be between 1 and 100")
    return WikidataSelection(provider, dataset, requested_limit)


def load_wikidata_brand_cache(path: Path) -> WikidataBrandCache:
    """로컬 JSON 캐시를 읽고 공급원·스키마·도메인을 엄격하게 검증한다."""
    with path.open("r", encoding="utf-8") as stream:
        value = json.load(stream)
    return WikidataBrandCache.from_mapping(_mapping(value, "cache"))


def write_wikidata_brand_cache(path: Path, cache: WikidataBrandCache) -> None:
    """완성된 캐시를 같은 디렉터리의 임시 파일을 거쳐 원자적으로 저장한다."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            json.dump(cache.to_dict(), stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        temporary_path.replace(path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def cached_requested_names(cache: WikidataBrandCache) -> tuple[str, ...]:
    """기존 캐시를 같은 브랜드 집합으로 갱신할 때 사용할 요청명을 반환한다."""
    return _unique_names(
        [entry.requested_name for entry in cache.brands]
        + [entry.requested_name for entry in cache.unresolved]
    )


def _unique_names(values: Iterable[str]) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        normalized = value.strip()
        folded = normalized.casefold()
        if normalized and folded not in seen:
            seen.add(folded)
            result.append(normalized)
    return tuple(result)


def _request_json(
    client: httpx.Client,
    params: Mapping[str, str | int],
    config: WikidataSyncConfig,
) -> Mapping[str, Any]:
    body = bytearray()
    with client.stream("GET", config.api_url, params=params) as response:
        response.raise_for_status()
        for chunk in response.iter_bytes():
            if len(body) + len(chunk) > config.max_response_bytes:
                raise WikidataPolicyError(
                    "Wikidata response exceeded configured max_response_bytes"
                )
            body.extend(chunk)
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WikidataPolicyError("Wikidata returned invalid JSON") from exc
    if not isinstance(value, Mapping):
        raise WikidataPolicyError("Wikidata returned a non-object response")
    if "error" in value:
        raise WikidataPolicyError(f"Wikidata API error: {value['error']}")
    return value


def _search_candidate_ids(
    client: httpx.Client,
    name: str,
    config: WikidataSyncConfig,
    *,
    languages: tuple[str, ...] | None = None,
) -> tuple[str, ...]:
    requested = name.casefold()
    candidates: list[str] = []
    for language in languages or config.languages:
        value = _request_json(
            client,
            {
                "action": "wbsearchentities",
                "search": name,
                "language": language,
                "uselang": language,
                "type": "item",
                "limit": config.max_search_results,
                "format": "json",
                "formatversion": 2,
            },
            config,
        )
        search = value.get("search", [])
        if not isinstance(search, list):
            raise WikidataPolicyError("Wikidata search response is invalid")
        for item in search:
            if not isinstance(item, Mapping):
                continue
            match = item.get("match")
            match_text = match.get("text") if isinstance(match, Mapping) else None
            texts = [item.get("label"), match_text]
            if not any(
                isinstance(text, str) and text.strip().casefold() == requested
                for text in texts
            ):
                continue
            candidate = item.get("id")
            if isinstance(candidate, str) and re.fullmatch(r"Q[1-9][0-9]*", candidate):
                if candidate not in candidates:
                    candidates.append(candidate)
    return tuple(candidates)


def _entity(
    client: httpx.Client, entity_id: str, config: WikidataSyncConfig
) -> Mapping[str, Any]:
    value = _request_json(
        client,
        {
            "action": "wbgetentities",
            "ids": entity_id,
            "props": "labels|aliases|claims|info",
            "languages": "|".join(config.languages),
            "languagefallback": 1,
            "format": "json",
            "formatversion": 2,
        },
        config,
    )
    entities = value.get("entities")
    if not isinstance(entities, Mapping):
        raise WikidataPolicyError("Wikidata entity response is invalid")
    return _mapping(entities.get(entity_id), f"entities.{entity_id}")


def _localized_values(value: Any, languages: tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(value, Mapping):
        return ()
    result: list[str] = []
    for language in languages:
        localized = value.get(language)
        items = localized if isinstance(localized, list) else [localized]
        for item in items:
            text = item.get("value") if isinstance(item, Mapping) else None
            if isinstance(text, str) and text.strip() and text.strip() not in result:
                result.append(text.strip())
    return tuple(result)


def _claim_end_time(claim: Mapping[str, Any]) -> datetime | None:
    qualifiers = claim.get("qualifiers")
    if not isinstance(qualifiers, Mapping):
        return None
    values = qualifiers.get("P582")
    if not isinstance(values, list) or not values:
        return None
    dates: list[datetime] = []
    for qualifier in values:
        if not isinstance(qualifier, Mapping):
            continue
        datavalue = qualifier.get("datavalue")
        raw = datavalue.get("value") if isinstance(datavalue, Mapping) else None
        time_value = raw.get("time") if isinstance(raw, Mapping) else None
        if not isinstance(time_value, str):
            continue
        try:
            dates.append(
                datetime.fromisoformat(time_value.lstrip("+").replace("Z", "+00:00"))
            )
        except ValueError:
            continue
    return min(dates) if dates else None


def _official_domains(entity: Mapping[str, Any], now: datetime) -> tuple[str, ...]:
    claims = entity.get("claims")
    websites = claims.get("P856", []) if isinstance(claims, Mapping) else []
    if not isinstance(websites, list):
        return ()
    active: list[Mapping[str, Any]] = []
    for claim in websites:
        if not isinstance(claim, Mapping) or claim.get("rank") == "deprecated":
            continue
        end_time = _claim_end_time(claim)
        if end_time is not None and end_time <= now:
            continue
        active.append(claim)
    preferred = [claim for claim in active if claim.get("rank") == "preferred"]
    selected = preferred or active
    result: list[str] = []
    for claim in selected:
        mainsnak = claim.get("mainsnak")
        if not isinstance(mainsnak, Mapping) or mainsnak.get("snaktype") != "value":
            continue
        datavalue = mainsnak.get("datavalue")
        url = datavalue.get("value") if isinstance(datavalue, Mapping) else None
        domain = etld1(url) if isinstance(url, str) else None
        if domain is not None and domain not in result:
            result.append(domain)
    return tuple(result)


def _brand_from_entity(
    requested_name: str,
    entity_id: str,
    entity: Mapping[str, Any],
    config: WikidataSyncConfig,
    now: datetime,
) -> WikidataBrandEntry | WikidataUnresolvedEntry:
    labels = _localized_values(entity.get("labels"), config.languages)
    aliases = _localized_values(entity.get("aliases"), config.languages)
    names = _unique_names((requested_name, *labels, *aliases))
    if requested_name.casefold() not in {value.casefold() for value in names}:
        return WikidataUnresolvedEntry(
            requested_name=requested_name,
            reason="entity_name_mismatch",
            candidate_ids=(entity_id,),
        )
    domains = _official_domains(entity, now)
    if not domains:
        return WikidataUnresolvedEntry(
            requested_name=requested_name,
            reason="no_current_official_website",
            candidate_ids=(entity_id,),
        )
    revision = entity.get("lastrevid")
    revision_id = revision if isinstance(revision, int) and revision > 0 else None
    label = labels[0] if labels else requested_name
    return WikidataBrandEntry(
        requested_name=requested_name,
        entity_id=entity_id,
        revision_id=revision_id,
        label=label,
        aliases=tuple(value for value in names if value.casefold() != label.casefold()),
        expected_domains=domains,
    )


def _domain_candidate_names(domain: str) -> tuple[str, ...]:
    """Domain 자체와 등록 Label 변형을 Wikidata exact search 후보로 만든다."""
    label = registrable_domain_label(domain)
    if label is None:
        return (domain,)
    try:
        decoded = label.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeEncodeError):
        decoded = label
    return _unique_names((domain, decoded, decoded.replace("-", " ")))


def _domain_brand_entry(
    client: httpx.Client,
    ranked_domain: RankedDomain,
    config: WikidataSyncConfig,
    now: datetime,
) -> WikidataBrandEntry | WikidataUnresolvedEntry:
    """Ranking Domain과 P856 eTLD+1이 실제로 일치하는 유일 Item만 확정한다."""
    observed_candidates: list[str] = []
    entities: dict[str, Mapping[str, Any]] = {}
    for candidate_name in _domain_candidate_names(ranked_domain.domain):
        candidate_ids = _search_candidate_ids(
            client, candidate_name, config, languages=("en",)
        )
        for entity_id in candidate_ids:
            if entity_id not in observed_candidates:
                observed_candidates.append(entity_id)
            if entity_id not in entities:
                entities[entity_id] = _entity(client, entity_id, config)
        matching: list[WikidataBrandEntry] = []
        for entity_id in candidate_ids:
            entry = _brand_from_entity(
                candidate_name, entity_id, entities[entity_id], config, now
            )
            if (
                isinstance(entry, WikidataBrandEntry)
                and ranked_domain.domain in entry.expected_domains
            ):
                matching.append(entry)
        if len(matching) == 1:
            return replace(
                matching[0],
                selection_domain=ranked_domain.domain,
                selection_rank=ranked_domain.rank,
            )
        if len(matching) > 1:
            return WikidataUnresolvedEntry(
                requested_name=ranked_domain.domain,
                reason="ambiguous_official_domain",
                candidate_ids=tuple(entry.entity_id for entry in matching),
            )
    return WikidataUnresolvedEntry(
        requested_name=ranked_domain.domain,
        reason="no_wikidata_official_domain_match",
        candidate_ids=tuple(observed_candidates),
    )


def sync_ranked_domains_to_wikidata_cache(
    ranked_domains: Iterable[RankedDomain],
    config: WikidataSyncConfig | None = None,
    *,
    transport: httpx.BaseTransport | None = None,
    now: datetime | None = None,
) -> WikidataBrandCache:
    """Cloudflare 후보 중 Wikidata P856으로 교차 확인된 브랜드만 캐시한다."""
    active_config = config or WikidataSyncConfig()
    domains = tuple(ranked_domains)
    if not domains:
        raise WikidataPolicyError("at least one ranked domain is required")
    if len(domains) > active_config.max_brands:
        raise WikidataPolicyError(
            f"domain count exceeds configured max_brands: {active_config.max_brands}"
        )
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    brands: list[WikidataBrandEntry] = []
    unresolved: list[WikidataUnresolvedEntry] = []
    with httpx.Client(
        timeout=active_config.request_timeout_seconds,
        transport=transport,
        trust_env=False,
        headers={
            "User-Agent": active_config.user_agent,
            "Accept-Encoding": "gzip, deflate",
        },
    ) as client:
        for ranked_domain in domains:
            entry = _domain_brand_entry(client, ranked_domain, active_config, current)
            if isinstance(entry, WikidataBrandEntry):
                if any(existing.entity_id == entry.entity_id for existing in brands):
                    continue
                if any(
                    existing.label.casefold() == entry.label.casefold()
                    for existing in brands
                ):
                    unresolved.append(
                        WikidataUnresolvedEntry(
                            ranked_domain.domain,
                            "duplicate_label",
                            tuple(
                                existing.entity_id
                                for existing in brands
                                if existing.label.casefold() == entry.label.casefold()
                            )
                            + (entry.entity_id,),
                        )
                    )
                    continue
                brands.append(entry)
            else:
                unresolved.append(entry)
    generated_at = (
        current.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    )
    return WikidataBrandCache(
        generated_at=generated_at,
        brands=tuple(brands),
        unresolved=tuple(unresolved),
        selection=WikidataSelection(
            provider="cloudflare_radar",
            dataset="domain_ranking_top",
            requested_limit=len(domains),
        ),
    )


def sync_wikidata_brand_cache(
    requested_names: Iterable[str],
    config: WikidataSyncConfig | None = None,
    *,
    transport: httpx.BaseTransport | None = None,
    now: datetime | None = None,
) -> WikidataBrandCache:
    """요청한 브랜드만 제한적으로 조회해 재현 가능한 로컬 캐시를 구성한다."""
    active_config = config or WikidataSyncConfig()
    names = _unique_names(requested_names)
    if not names:
        raise WikidataPolicyError("at least one brand name is required")
    if len(names) > active_config.max_brands:
        raise WikidataPolicyError(
            f"brand count exceeds configured max_brands: {active_config.max_brands}"
        )
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    brands: list[WikidataBrandEntry] = []
    unresolved: list[WikidataUnresolvedEntry] = []
    with httpx.Client(
        timeout=active_config.request_timeout_seconds,
        transport=transport,
        trust_env=False,
        headers={
            "User-Agent": active_config.user_agent,
            "Accept-Encoding": "gzip, deflate",
        },
    ) as client:
        for name in names:
            candidate_ids = _search_candidate_ids(client, name, active_config)
            if not candidate_ids:
                unresolved.append(
                    WikidataUnresolvedEntry(name, "not_found", candidate_ids)
                )
                continue
            if len(candidate_ids) != 1:
                unresolved.append(
                    WikidataUnresolvedEntry(name, "ambiguous", candidate_ids)
                )
                continue
            entity_id = candidate_ids[0]
            entry = _brand_from_entity(
                name,
                entity_id,
                _entity(client, entity_id, active_config),
                active_config,
                current,
            )
            if isinstance(entry, WikidataBrandEntry):
                same_entity_index = next(
                    (
                        index
                        for index, existing in enumerate(brands)
                        if existing.entity_id == entry.entity_id
                    ),
                    None,
                )
                if same_entity_index is not None:
                    existing = brands[same_entity_index]
                    aliases = _unique_names(
                        (*existing.aliases, entry.requested_name, *entry.aliases)
                    )
                    brands[same_entity_index] = replace(
                        existing,
                        aliases=tuple(
                            alias
                            for alias in aliases
                            if alias.casefold() != existing.label.casefold()
                        ),
                    )
                    continue
                same_label = next(
                    (
                        existing
                        for existing in brands
                        if existing.label.casefold() == entry.label.casefold()
                    ),
                    None,
                )
                if same_label is not None:
                    unresolved.append(
                        WikidataUnresolvedEntry(
                            name,
                            "duplicate_label",
                            (same_label.entity_id, entry.entity_id),
                        )
                    )
                    continue
                brands.append(entry)
            else:
                unresolved.append(entry)
    generated_at = (
        current.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    )
    return WikidataBrandCache(
        generated_at=generated_at,
        brands=tuple(brands),
        unresolved=tuple(unresolved),
    )


__all__ = [
    "WIKIDATA_API_URL",
    "WIKIDATA_CACHE_SCHEMA_VERSION",
    "WIKIDATA_PROVIDER_NAME",
    "WikidataBrandCache",
    "WikidataBrandEntry",
    "WikidataPolicyError",
    "WikidataSelection",
    "WikidataSyncConfig",
    "WikidataUnresolvedEntry",
    "cached_requested_names",
    "load_wikidata_brand_cache",
    "sync_wikidata_brand_cache",
    "sync_ranked_domains_to_wikidata_cache",
    "write_wikidata_brand_cache",
]
