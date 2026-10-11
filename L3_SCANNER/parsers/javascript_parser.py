"""공유 JavaScript Raw Observation을 만드는 정적 분석 공개 진입점.

스크립트 Source를 한 번 ESTree로 파싱하고 모든 JavaScript Signal이 공유하는 이벤트를
생성한다. 코드 실행, 외부 요청, 브라우저 제어는 수행하지 않는다.
"""

from __future__ import annotations

from typing import Any, Mapping

from L3_SCANNER.models.input import L3Input
from L3_SCANNER.models.raw import empty_javascript_raw
from L3_SCANNER.parsers.javascript.analyzer import StaticAnalyzer
from L3_SCANNER.parsers.javascript.ast import parse_source, parser_available, walk
from L3_SCANNER.parsers.javascript.limits import enforce_event_limit
from L3_SCANNER.parsers.javascript.metadata import credential_fields, script_metadata
from L3_SCANNER.parsers.javascript.static_data import collect_literal_declarations, collect_json_data
from L3_SCANNER.parsers.javascript.request_context import enrich_request_context
from L3_SCANNER.policies.detection import DetectionPolicy
from L3_SCANNER.policies.runtime import RuntimeConfig
from L3_SCANNER.utils.url import etld1


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
    from L3_SCANNER.analyzers.credential_classification import classification_result
    prepared_html=dict(html_raw or {})
    classification=classification_result(prepared_html,active_policy)
    prepared_html['credential_classification']=classification
    fields = credential_fields(prepared_html, active_policy)
    raw["analysis"] = _analysis_metadata(scan_input, active_policy)
    raw['analysis']['credential_classification_state']=classification['state']
    raw['errors'].extend(classification['errors'])
    if classification['errors']:raw['analysis']['semantic_complete']=False

    global_variables = {}
    global_functions = {}
    for script in scan_input.scripts:
        metadata = script_metadata(script)
        raw["scripts"].append(metadata)
        decoding_errors=[e for e in script.collection_errors if e.get('code') in {'decoding_loss','unknown_encoding'}]
        if decoding_errors:
            raw['analysis']['decoding_complete']=False
            raw['analysis']['source_complete']=False
            raw['errors'].extend({**e,'script_id':script.script_id} for e in decoding_errors)
        media_type = (script.media_type or "").split(";", 1)[0].strip().lower()
        if media_type not in {"", "text/javascript", "application/javascript", "text/ecmascript", "application/ecmascript", "module"}:
            metadata["analysis_status"] = "data_block"
            if media_type in {"application/json", "application/ld+json"}:
                collect_json_data(raw, script, active_runtime.max_script_bytes)
            continue
        ordered = not script.async_script and not script.defer_script and media_type != "module"
        if not ordered:
            global_variables.clear()
            global_functions.clear()
            raw["analysis"]["semantic_complete"] = False
            raw["errors"].append({"code":"script_order_unresolved", "script_id":script.script_id,
                                  "message":"Module/async/defer binding and execution order not established"})
        if script.source is None:
            global_variables.clear()
            global_functions.clear()
            _mark_missing_source(raw, metadata, script.script_id)
            continue

        actual_size = len(script.source.encode("utf-8", errors="replace"))
        if actual_size > active_runtime.max_script_bytes:
            global_variables.clear()
            global_functions.clear()
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
            global_variables.clear()
            global_functions.clear()
            _mark_parser_unavailable(raw, metadata, script.script_id)
            continue

        try:
            tree = parse_source(script.source)
        except Exception as exc:
            global_variables.clear()
            global_functions.clear()
            _mark_parse_error(raw, metadata, script.script_id, exc)
            continue

        metadata["analysis_status"] = "parsed"
        # AST 노드 수는 분석 규모와 제한 정책을 점검할 수 있는 진단 메타데이터다.
        metadata["ast_node_count"] = sum(1 for _ in walk(tree))
        raw["analysis"]["parsed_script_count"] += 1
        collect_literal_declarations(raw, script, tree)
        analyzer = StaticAnalyzer(
            raw=raw,
            script=script,
            source=script.source,
            document_url=scan_input.document_url,
            policy=active_policy,
            credential_fields=fields,
        )
        analyzer.effective_base_url = (html_raw or {}).get("document", {}).get("effective_base_url") or scan_input.document_url
        if ordered:
            analyzer.variables = global_variables
            analyzer.functions = global_functions
        analyzed_all_nodes=True
        try:
            analyzer.analyze(tree)
            enrich_request_context(raw, script, tree)
        except (ValueError, RecursionError) as exc:
            analyzed_all_nodes=False
            analyzer._limitation("javascript_analysis_limit", str(exc))
        if ordered and not script.truncated and analyzed_all_nodes:
            global_variables, global_functions = analyzer.variables, analyzer.functions
        else:
            global_variables.clear()
            global_functions.clear()
        enforce_event_limit(raw, active_runtime.max_javascript_events)
    return raw


def _analysis_metadata(scan_input: L3Input, policy: DetectionPolicy) -> dict[str, Any]:
    """분석 완전성과 각 Open Policy의 설정 여부를 결과에 명시한다."""
    return {
        "document_url": scan_input.document_url,
        "document_etld1": etld1(scan_input.document_url),
        "source_complete": True,
        "semantic_complete": True,
        "decoding_complete": True,
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
            "message": "Script source is unavailable to analysis; consult collection_errors for attempted, failed or limited acquisition.",
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
