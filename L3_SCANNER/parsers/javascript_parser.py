"""공유 JavaScript Raw Observation을 만드는 정적 분석 공개 진입점.

스크립트 Source를 한 번 ESTree로 파싱하고 모든 JavaScript Signal이 공유하는 이벤트를
생성한다. 코드 실행, 외부 요청, 브라우저 제어는 수행하지 않는다.
"""

from __future__ import annotations

from typing import Any, Mapping

from ..models.input import L3Input
from ..models.raw import empty_javascript_raw
from ..policies.detection import DetectionPolicy
from ..policies.runtime import RuntimeConfig
from ..utils.url import etld1
from .javascript.analyzer import StaticAnalyzer
from .javascript.ast import parse_source, parser_available, walk
from .javascript.limits import enforce_event_limit
from .javascript.metadata import credential_fields, script_metadata


def parse_javascript(
    scan_input: L3Input,
    html_raw: Mapping[str, Any] | None = None,
    policy: DetectionPolicy | None = None,
    runtime: RuntimeConfig | None = None,
) -> dict[str, Any]:
    """확보된 스크립트를 I/O나 실행 없이 한 번씩 파싱해 공통 Raw를 만든다.

    Source 부재·크기 초과·Parser 실패를 스크립트별 상태로 남긴다. 하나의 실패가 다른
    스크립트 분석을 중단시키지 않으며, 불완전한 분석은 음성 Signal 확정을 막는다.
    """
    raw = empty_javascript_raw()
    active_policy = policy or DetectionPolicy()
    active_runtime = runtime or RuntimeConfig()
    fields = credential_fields(html_raw or {}, active_policy)
    raw["analysis"] = _analysis_metadata(scan_input, active_policy)

    for script in scan_input.scripts:
        metadata = script_metadata(script)
        raw["scripts"].append(metadata)
        if script.source is None:
            _mark_missing_source(raw, metadata, script.script_id)
            continue

        actual_size = len(script.source.encode("utf-8", errors="replace"))
        if actual_size > active_runtime.max_script_bytes:
            _mark_source_limit(
                raw,
                metadata,
                script.script_id,
                actual_size,
                active_runtime.max_script_bytes,
            )
            continue
        if script.truncated:
            raw["analysis"]["source_complete"] = False
        if not parser_available():
            _mark_parser_unavailable(raw, metadata, script.script_id)
            continue

        try:
            tree = parse_source(script.source)
        except Exception as exc:
            _mark_parse_error(raw, metadata, script.script_id, exc)
            continue

        metadata["analysis_status"] = "parsed"
        # AST 노드 수는 분석 규모와 제한 정책을 점검할 수 있는 진단 메타데이터다.
        metadata["ast_node_count"] = sum(1 for _ in walk(tree))
        raw["analysis"]["parsed_script_count"] += 1
        StaticAnalyzer(
            raw=raw,
            script=script,
            source=script.source,
            document_url=scan_input.document_url,
            policy=active_policy,
            credential_fields=fields,
        ).analyze(tree)
        enforce_event_limit(raw, active_runtime.max_javascript_events)
    return raw


def _analysis_metadata(scan_input: L3Input, policy: DetectionPolicy) -> dict[str, Any]:
    """분석 완전성과 각 Open Policy의 설정 여부를 결과에 명시한다."""
    return {
        "document_url": scan_input.document_url,
        "document_etld1": etld1(scan_input.document_url),
        "source_complete": True,
        "parsed_script_count": 0,
        "credential_policy_configured": policy.credential_classifier is not None,
        "dynamic_execution_policy_configured": policy.dynamic_execution_apis
        is not None,
        "decode_policy_configured": policy.decode_methods is not None,
        "network_policy_configured": policy.network_apis is not None,
        "redirect_policy_configured": policy.redirect_apis is not None,
        "anti_bot_policy_configured": policy.anti_bot_properties is not None,
        "branch_behavior_policy_configured": policy.branch_behavior_normalizer
        is not None,
    }


def _mark_missing_source(
    raw: dict[str, Any], metadata: dict[str, Any], script_id: str
) -> None:
    """Source 미제공을 오류로 보존하고 분석 완전성을 낮춘다."""
    metadata["analysis_status"] = "missing_source"
    raw["analysis"]["source_complete"] = False
    raw["errors"].append(
        {
            "code": "javascript_source_unavailable",
            "script_id": script_id,
            "message": "Script source was not supplied; no fetch was attempted.",
        }
    )


def _mark_source_limit(
    raw: dict[str, Any],
    metadata: dict[str, Any],
    script_id: str,
    size: int,
    limit: int,
) -> None:
    """크기 상한을 넘은 Source를 파싱하지 않고 제한 정보를 기록한다."""
    metadata["analysis_status"] = "source_limit_exceeded"
    raw["analysis"]["source_complete"] = False
    raw["errors"].append(
        {
            "code": "javascript_source_limit_exceeded",
            "script_id": script_id,
            "message": "Script source exceeds the configured analysis limit.",
            "size": size,
            "limit": limit,
        }
    )


def _mark_parser_unavailable(
    raw: dict[str, Any], metadata: dict[str, Any], script_id: str
) -> None:
    """구조적 Parser 의존성 부재를 스크립트별 분석 불가로 기록한다."""
    metadata["analysis_status"] = "parser_unavailable"
    raw["analysis"]["source_complete"] = False
    raw["errors"].append(
        {
            "code": "javascript_parser_unavailable",
            "script_id": script_id,
            "message": "The esprima dependency is required for structural parsing.",
        }
    )


def _mark_parse_error(
    raw: dict[str, Any], metadata: dict[str, Any], script_id: str, exc: Exception
) -> None:
    """신뢰할 수 없는 Source의 구문 파싱 실패를 다른 스크립트와 격리한다."""
    metadata["analysis_status"] = "parse_error"
    raw["analysis"]["source_complete"] = False
    raw["errors"].append(
        {"code": "javascript_parse_error", "script_id": script_id, "message": str(exc)}
    )
