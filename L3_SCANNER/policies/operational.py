"""버전 관리되는 JSON 설정에서 범용 L3 운영 탐지 정책을 구성한다."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from importlib.resources import files
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from L3_SCANNER.brands.wikidata import (
    WIKIDATA_PROVIDER_NAME,
    WikidataBrandCache,
    load_wikidata_brand_cache,
)
from L3_SCANNER.policies.detection import DetectionPolicy
from L3_SCANNER.utils.url import etld1

DEFAULT_OPERATIONAL_POLICY_NAME = "operational-v1"
DEFAULT_OPERATIONAL_POLICY_RESOURCE = "operational.v1.json"


class PolicyConfigurationError(ValueError):
    """운영 정책 JSON이 지원 계약을 위반했음을 나타낸다."""


@dataclass(frozen=True, slots=True)
class CredentialRules:
    type_mapping: Mapping[str, str]
    autocomplete_mapping: Mapping[str, str]
    identifier_tokens: Mapping[str, tuple[str, ...]]


@dataclass(frozen=True, slots=True)
class BrandRule:
    title_tokens: tuple[str, ...]
    site_name_tokens: tuple[str, ...]
    hostname_tokens: tuple[str, ...]
    expected_domains: tuple[str, ...]
    resource_domains: tuple[str, ...]
    resource_policy_available: bool = True
    provider: str | None = None
    provider_entity_id: str | None = None


@dataclass(frozen=True, slots=True)
class JavascriptRules:
    dynamic_execution_apis: frozenset[str]
    decode_methods: frozenset[str]
    network_apis: frozenset[str]
    redirect_apis: frozenset[str]
    anti_bot_properties: frozenset[str]
    branch_behavior_normalization: str


@dataclass(frozen=True, slots=True)
class OperationalPolicyConfig:
    """검증을 마친 운영 정책 값."""

    schema_version: str
    policy_name: str
    credential_fields: CredentialRules
    brands: Mapping[str, BrandRule]
    shared_resource_domains: tuple[str, ...]
    javascript: JavascriptRules

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "OperationalPolicyConfig":
        """알 수 없는 필드와 잘못된 타입을 거부해 정책 오타를 조기에 차단한다."""
        _reject_unknown(
            value,
            {
                "schema_version",
                "policy_name",
                "credential_fields",
                "brands",
                "brand_resources",
                "javascript",
            },
            "policy",
        )
        schema_version = _required_string(value, "schema_version", "policy")
        if schema_version != "1.0":
            raise PolicyConfigurationError(
                f"unsupported policy schema_version: {schema_version}"
            )
        policy_name = _required_string(value, "policy_name", "policy")
        credential = _credential_rules(
            _required_mapping(value, "credential_fields", "policy")
        )
        brands = _brand_rules(_required_mapping(value, "brands", "policy"))
        resources = _required_mapping(value, "brand_resources", "policy")
        _reject_unknown(resources, {"shared_domains"}, "brand_resources")
        shared_domains = _domains(
            resources.get("shared_domains"), "brand_resources.shared_domains"
        )
        javascript = _javascript_rules(_required_mapping(value, "javascript", "policy"))
        return cls(
            schema_version=schema_version,
            policy_name=policy_name,
            credential_fields=credential,
            brands=brands,
            shared_resource_domains=shared_domains,
            javascript=javascript,
        )


def _reject_unknown(value: Mapping[str, Any], allowed: set[str], path: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise PolicyConfigurationError(f"unknown fields at {path}: {unknown}")


def _required_mapping(
    value: Mapping[str, Any], key: str, path: str
) -> Mapping[str, Any]:
    item = value.get(key)
    if not isinstance(item, Mapping):
        raise PolicyConfigurationError(f"{path}.{key} must be an object")
    return item


def _required_string(value: Mapping[str, Any], key: str, path: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item.strip():
        raise PolicyConfigurationError(f"{path}.{key} must be a non-empty string")
    return item.strip()


def _string_mapping(value: Any, path: str) -> dict[str, str]:
    if not isinstance(value, Mapping) or not value:
        raise PolicyConfigurationError(f"{path} must be a non-empty object")
    result: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key.strip():
            raise PolicyConfigurationError(f"{path} keys must be non-empty strings")
        if not isinstance(item, str) or not item.strip():
            raise PolicyConfigurationError(f"{path}.{key} must be a non-empty string")
        result[key.strip().casefold()] = item.strip().casefold()
    return result


def _strings(value: Any, path: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise PolicyConfigurationError(f"{path} must be an array")
    if not value and not allow_empty:
        raise PolicyConfigurationError(f"{path} must not be empty")
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            raise PolicyConfigurationError(
                f"{path}[{index}] must be a non-empty string"
            )
        normalized = item.strip()
        if normalized not in result:
            result.append(normalized)
    return tuple(result)


def _domains(value: Any, path: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    domains = _strings(value, path, allow_empty=allow_empty)
    result: list[str] = []
    for item in domains:
        normalized = etld1(f"https://{item.strip().lower().rstrip('.')}")
        if normalized is None:
            raise PolicyConfigurationError(f"{path} contains an invalid domain: {item}")
        if normalized not in result:
            result.append(normalized)
    return tuple(result)


def _credential_rules(value: Mapping[str, Any]) -> CredentialRules:
    _reject_unknown(
        value,
        {"type_mapping", "autocomplete_mapping", "identifier_tokens"},
        "credential_fields",
    )
    identifiers = _required_mapping(value, "identifier_tokens", "credential_fields")
    identifier_tokens = {
        str(kind).strip().casefold(): _strings(
            tokens, f"credential_fields.identifier_tokens.{kind}"
        )
        for kind, tokens in identifiers.items()
        if str(kind).strip()
    }
    if not identifier_tokens:
        raise PolicyConfigurationError(
            "credential_fields.identifier_tokens must not be empty"
        )
    normalized_tokens: dict[str, str] = {}
    for kind, tokens in identifier_tokens.items():
        for token in tokens:
            normalized = _compact(token)
            previous = normalized_tokens.get(normalized)
            if previous is not None and previous != kind:
                raise PolicyConfigurationError(
                    "credential identifier token is assigned to multiple types: "
                    f"{token}"
                )
            normalized_tokens[normalized] = kind
    return CredentialRules(
        type_mapping=_string_mapping(
            value.get("type_mapping"), "credential_fields.type_mapping"
        ),
        autocomplete_mapping=_string_mapping(
            value.get("autocomplete_mapping"),
            "credential_fields.autocomplete_mapping",
        ),
        identifier_tokens=identifier_tokens,
    )


def _brand_rules(value: Mapping[str, Any]) -> dict[str, BrandRule]:
    result: dict[str, BrandRule] = {}
    for brand, raw_rule in value.items():
        if not isinstance(brand, str) or not brand.strip():
            raise PolicyConfigurationError("brand keys must be non-empty strings")
        if not isinstance(raw_rule, Mapping):
            raise PolicyConfigurationError(f"brands.{brand} must be an object")
        path = f"brands.{brand}"
        _reject_unknown(
            raw_rule,
            {
                "title_tokens",
                "site_name_tokens",
                "hostname_tokens",
                "expected_domains",
                "resource_domains",
            },
            path,
        )
        title_tokens = _strings(
            raw_rule.get("title_tokens"), f"{path}.title_tokens", allow_empty=True
        )
        site_name_tokens = _strings(
            raw_rule.get("site_name_tokens"),
            f"{path}.site_name_tokens",
            allow_empty=True,
        )
        hostname_tokens = _hostname_tokens(
            raw_rule.get("hostname_tokens"), f"{path}.hostname_tokens"
        )
        if not title_tokens and not site_name_tokens and not hostname_tokens:
            raise PolicyConfigurationError(
                f"{path} needs at least one title, site-name, or hostname token"
            )
        result[brand.strip()] = BrandRule(
            title_tokens=title_tokens,
            site_name_tokens=site_name_tokens,
            hostname_tokens=hostname_tokens,
            expected_domains=_domains(
                raw_rule.get("expected_domains"),
                f"{path}.expected_domains",
                allow_empty=False,
            ),
            resource_domains=_domains(
                raw_rule.get("resource_domains"), f"{path}.resource_domains"
            ),
        )
    return result


def _hostname_tokens(value: Any, path: str) -> tuple[str, ...]:
    tokens = _strings(value, path, allow_empty=True)
    result: list[str] = []
    for item in tokens:
        if any(character in item for character in ".:/@"):
            raise PolicyConfigurationError(
                f"{path} must contain hostname-label tokens, not URLs: {item}"
            )
        try:
            normalized = item.encode("idna").decode("ascii").casefold()
        except UnicodeError as exc:
            raise PolicyConfigurationError(
                f"{path} contains an invalid IDNA token: {item}"
            ) from exc
        if not normalized or normalized.startswith("-") or normalized.endswith("-"):
            raise PolicyConfigurationError(
                f"{path} contains an invalid hostname token: {item}"
            )
        if normalized not in result:
            result.append(normalized)
    return tuple(result)


def _javascript_rules(value: Mapping[str, Any]) -> JavascriptRules:
    allowed = {
        "dynamic_execution_apis",
        "decode_methods",
        "network_apis",
        "redirect_apis",
        "anti_bot_properties",
        "branch_behavior_normalization",
    }
    _reject_unknown(value, allowed, "javascript")
    normalization = _required_string(
        value, "branch_behavior_normalization", "javascript"
    )
    if normalization != "canonical_json":
        raise PolicyConfigurationError(
            "javascript.branch_behavior_normalization must be canonical_json"
        )
    return JavascriptRules(
        dynamic_execution_apis=frozenset(
            _strings(
                value.get("dynamic_execution_apis"),
                "javascript.dynamic_execution_apis",
            )
        ),
        decode_methods=frozenset(
            _strings(value.get("decode_methods"), "javascript.decode_methods")
        ),
        network_apis=frozenset(
            _strings(value.get("network_apis"), "javascript.network_apis")
        ),
        redirect_apis=frozenset(
            _strings(value.get("redirect_apis"), "javascript.redirect_apis")
        ),
        anti_bot_properties=frozenset(
            _strings(
                value.get("anti_bot_properties"),
                "javascript.anti_bot_properties",
            )
        ),
        branch_behavior_normalization=normalization,
    )


def _compact(value: str) -> str:
    return "".join(re.split(r"[\W_]+", value.casefold()))


def _field_terms(value: object) -> set[str]:
    text = str(value or "").strip().casefold()
    words = {word for word in re.split(r"[\W_]+", text) if word}
    compact = _compact(text)
    return words | ({compact} if compact else set())


def _credential_classifier(config: OperationalPolicyConfig):
    rules = config.credential_fields
    token_types = {
        _compact(token): credential_type
        for credential_type, tokens in rules.identifier_tokens.items()
        for token in tokens
    }

    def classify(field: Mapping[str, Any]) -> str | None:
        field_type = str(field.get("type") or "").strip().casefold()
        if field_type in rules.type_mapping:
            return rules.type_mapping[field_type]
        autocomplete = str(field.get("autocomplete") or "").strip().casefold()
        for token in autocomplete.split():
            if token in rules.autocomplete_mapping:
                return rules.autocomplete_mapping[token]
        terms = set().union(
            *(
                _field_terms(field.get(key))
                for key in ("html_id", "name", "placeholder")
            )
        )
        matches = {token_types[term] for term in terms if term in token_types}
        return next(iter(matches)) if len(matches) == 1 else None

    return classify


def _brand_identifier(config: OperationalPolicyConfig):
    def hostname_labels(document: Mapping[str, Any]) -> tuple[str, ...]:
        try:
            hostname = urlsplit(str(document.get("url") or "")).hostname
            if hostname is None:
                return ()
            ascii_hostname = hostname.encode("idna").decode("ascii").casefold()
        except (UnicodeError, ValueError):
            return ()
        return tuple(label for label in ascii_hostname.split(".") if label)

    def hostname_matches(labels: tuple[str, ...], token: str) -> bool:
        return any(
            label == token
            or label.startswith(f"{token}-")
            or label.endswith(f"-{token}")
            or f"-{token}-" in label
            for label in labels
        )

    def identify(context: Mapping[str, Any]) -> str | Mapping[str, Any] | None:
        document = context.get("document") or {}
        title = str(document.get("title") or "").casefold()
        site_name = str(
            (context.get("open_graph") or {}).get("og:site_name", {}).get("raw_content")
            or ""
        ).casefold()
        labels = hostname_labels(document)
        matches: list[tuple[str, list[str]]] = []
        for brand, rule in config.brands.items():
            sources = []
            if any(token.casefold() in title for token in rule.title_tokens):
                sources.append("title")
            if any(token.casefold() in site_name for token in rule.site_name_tokens):
                sources.append("og_site_name")
            if any(hostname_matches(labels, token) for token in rule.hostname_tokens):
                sources.append("hostname")
            if sources:
                matches.append((brand, sources))
        if len(matches) != 1:
            return None
        brand, sources = matches[0]
        return {
            "brand": brand,
            "sources": sources,
            "confidence": (
                "high" if any(source != "hostname" for source in sources) else "low"
            ),
            "provider": rule.provider,
            "provider_entity_id": rule.provider_entity_id,
        }

    return identify


def _brand_resource_evaluator(config: OperationalPolicyConfig):
    def evaluate(evidence: Mapping[str, Any]) -> bool | None:
        brand = evidence.get("detected_brand")
        current = evidence.get("current_domain")
        rule = config.brands.get(str(brand)) if brand is not None else None
        if rule is None or current is None:
            return None
        allowed = {
            str(current),
            *rule.expected_domains,
            *rule.resource_domains,
            *config.shared_resource_domains,
        }
        has_unexpected_resource = any(
            resource.get("resource_domain") is not None
            and resource.get("resource_domain") not in allowed
            for resource in evidence.get("resources", [])
        )
        if not has_unexpected_resource:
            return False
        return True if rule.resource_policy_available else None

    return evaluate


def _normalize_branch(branch: Mapping[str, Any]) -> str:
    return json.dumps(
        branch.get("observations", []),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def load_operational_policy_config(
    path: Path | None = None,
) -> OperationalPolicyConfig:
    """Bundled 기본값 또는 지정 JSON을 읽어 검증된 운영 설정을 반환한다."""
    if path is None:
        resource = files("L3_SCANNER.policies").joinpath(
            DEFAULT_OPERATIONAL_POLICY_RESOURCE
        )
        with resource.open("r", encoding="utf-8") as stream:
            value = json.load(stream)
    else:
        with path.open("r", encoding="utf-8") as stream:
            value = json.load(stream)
    if not isinstance(value, Mapping):
        raise PolicyConfigurationError("policy document must be a JSON object")
    return OperationalPolicyConfig.from_mapping(value)


def _wikidata_hostname_tokens(values: tuple[str, ...]) -> tuple[str, ...]:
    """Wikidata label/alias를 Hostname Label 비교용 결정적 Token으로 변환한다."""
    result: list[str] = []
    for value in values:
        compact = "".join(character for character in value if character.isalnum())
        if not compact:
            continue
        try:
            token = compact.encode("idna").decode("ascii").casefold()
        except UnicodeError:
            continue
        if token not in result:
            result.append(token)
    return tuple(result)


def _wikidata_brand_rules(cache: WikidataBrandCache) -> Mapping[str, BrandRule]:
    """P856 캐시를 기존 Analyzer가 소비하는 BrandRule 집합으로 변환한다."""
    result: dict[str, BrandRule] = {}
    for entry in cache.brands:
        names = tuple(
            dict.fromkeys((entry.requested_name, entry.label, *entry.aliases))
        )
        if entry.label in result:
            raise PolicyConfigurationError(
                f"Wikidata cache contains a duplicate brand label: {entry.label}"
            )
        result[entry.label] = BrandRule(
            title_tokens=names,
            site_name_tokens=names,
            hostname_tokens=_wikidata_hostname_tokens(names),
            expected_domains=entry.expected_domains,
            resource_domains=(),
            # P856은 공식 웹사이트만 제공하며 CDN/자산 소유 관계를 제공하지 않는다.
            resource_policy_available=False,
            provider=WIKIDATA_PROVIDER_NAME,
            provider_entity_id=entry.entity_id,
        )
    return result


def operational_detection_policy(
    path: Path | None = None,
    wikidata_cache_path: Path | None = None,
) -> DetectionPolicy:
    """검증된 버전 정책을 Analyzer가 사용하는 공통 DetectionPolicy로 변환한다."""
    config = load_operational_policy_config(path)
    brand_policy_metadata: Mapping[str, Any] | None = None
    if wikidata_cache_path is not None:
        if config.brands or config.shared_resource_domains:
            raise PolicyConfigurationError(
                "operational brands and shared resource domains must be empty when "
                "Wikidata is the brand provider"
            )
        cache = load_wikidata_brand_cache(wikidata_cache_path)
        config = replace(config, brands=_wikidata_brand_rules(cache))
        brand_policy_metadata = {
            "provider": cache.provider,
            "schema_version": cache.schema_version,
            "generated_at": cache.generated_at,
            "resolved_brand_count": len(cache.brands),
            "unresolved_brand_count": len(cache.unresolved),
            "selection": (
                cache.selection.to_dict() if cache.selection is not None else None
            ),
        }
    javascript = config.javascript
    return DetectionPolicy(
        credential_classifier=_credential_classifier(config),
        brand_identifier=_brand_identifier(config),
        brand_expected_domains={
            brand: rule.expected_domains for brand, rule in config.brands.items()
        },
        brand_resource_rules={
            "evaluator": _brand_resource_evaluator(config),
            "policy_name": config.policy_name,
        },
        dynamic_execution_apis=javascript.dynamic_execution_apis,
        decode_methods=javascript.decode_methods,
        network_apis=javascript.network_apis,
        redirect_apis=javascript.redirect_apis,
        anti_bot_properties=javascript.anti_bot_properties,
        branch_behavior_normalizer=_normalize_branch,
        policy_name=config.policy_name,
        brand_policy_metadata=brand_policy_metadata,
    )


__all__ = [
    "BrandRule",
    "CredentialRules",
    "DEFAULT_OPERATIONAL_POLICY_NAME",
    "DEFAULT_OPERATIONAL_POLICY_RESOURCE",
    "JavascriptRules",
    "OperationalPolicyConfig",
    "PolicyConfigurationError",
    "load_operational_policy_config",
    "operational_detection_policy",
]
