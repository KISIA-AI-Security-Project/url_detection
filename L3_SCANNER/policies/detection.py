"""명시적으로 주입하고 버전 관리할 수 있는 탐지 정책 입력.

각 필드의 ``None``은 기본 정책이 아니라 '정책 미확정'을 의미한다. 해당 정책이
필요한 Analyzer는 객관적인 Raw Evidence를 보존하고 ``detected=None``을 반환해야
한다. 브랜드 목록이나 API 집합을 구현 편의를 위해 이 모듈에 임의로 추가하지 않는다.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

CredentialClassifier = Callable[[Mapping[str, Any]], str | None]
BrandIdentifier = Callable[[Mapping[str, Any]], str | Mapping[str, Any] | None]
BranchBehaviorNormalizer = Callable[[Mapping[str, Any]], str | None]


@dataclass(slots=True)
class DetectionPolicy:
    """Signal 판단에 사용되는 선택적 정책 모음.

    Callable 정책은 Raw 구조만 입력받아야 하며 네트워크 수집이나 저장 같은 부수
    효과를 만들지 않아야 한다. 런타임 제한값은 ``RuntimeConfig``가 담당한다.
    """

    credential_classifier: CredentialClassifier | None = None
    brand_identifier: BrandIdentifier | None = None
    brand_expected_domains: Mapping[str, tuple[str, ...]] | None = None
    brand_resource_rules: Mapping[str, Any] | None = None
    dynamic_execution_apis: frozenset[str] | None = None
    decode_methods: frozenset[str] | None = None
    network_apis: frozenset[str] | None = None
    redirect_apis: frozenset[str] | None = None
    anti_bot_properties: frozenset[str] | None = None
    branch_behavior_normalizer: BranchBehaviorNormalizer | None = None
    policy_name: str | None = None
    brand_policy_metadata: Mapping[str, Any] | None = None
