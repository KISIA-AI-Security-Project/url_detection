"""독립 URL 수집과 외부 콘텐츠 분석을 연결하는 L3 오케스트레이터.

두 진입점은 수집 이후 반드시 동일한 HTML/JavaScript Parser와 Analyzer 경로를
사용한다. 이 모듈은 결과를 조립하지만 Signal별 탐지 규칙이나 최종 악성/정상 판정을
포함하지 않는다.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime
import gc
from threading import RLock
from typing import Any, Mapping

from L3_SCANNER.analyzers.html.runner import analyze_html
from L3_SCANNER.analyzers.credential_classification import classify_credential_fields
from L3_SCANNER.analyzers.html.native_submission import analyze_native_submission
from L3_SCANNER.analyzers.javascript.runner import analyze_javascript
from L3_SCANNER.collectors import collect_external_script, collect_page
from L3_SCANNER.models.input import L3Input, ScriptInput
from L3_SCANNER.parsers.html_parser import parse_html
from L3_SCANNER.parsers.javascript_parser import parse_javascript
from L3_SCANNER.parsers.javascript.static_data import analyze_static_data
from L3_SCANNER.policies.detection import DetectionPolicy
from L3_SCANNER.policies.runtime import RuntimeConfig
from L3_SCANNER.utils.url import etld1

SCHEMA_VERSION = "1.0"
_HTML_CONTENT_TYPES = {"text/html", "application/xhtml+xml"}
_JAVASCRIPT_GC_LOCK = RLock()


def _parse_javascript_with_deferred_gc(
    scan_input: L3Input,
    html_raw: Mapping[str, Any],
    policy: DetectionPolicy,
    runtime: RuntimeConfig,
) -> dict[str, Any]:
    """Collect temporary AST cycles after parsing and analysis have returned.

    Reference counting remains active. The parser and analyzer have released
    their large temporary trees before the explicit collection below. Cleanup
    stays inside the caller's L3 duration, including on an exception. The lock
    coordinates this process-wide GC setting between L3 calls; other threads
    in the process also defer cyclic collection during this short scope.
    """
    if not any(script.source for script in scan_input.scripts):
        return parse_javascript(scan_input, html_raw, policy, runtime)
    with _JAVASCRIPT_GC_LOCK:
        was_enabled = gc.isenabled()
        if was_enabled:
            gc.disable()
        try:
            return parse_javascript(scan_input, html_raw, policy, runtime)
        finally:
            if was_enabled:
                try:
                    gc.collect()
                finally:
                    gc.enable()


def _now_iso() -> str:
    """스캔 메타데이터에 사용할 현재 지역 시각을 초 단위 ISO 문자열로 만든다."""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _copy_input(value: L3Input | Mapping[str, Any]) -> L3Input:
    """호출자가 제공한 입력을 수정하지 않도록 독립된 ``L3Input``을 만든다."""
    if isinstance(value, L3Input):
        return deepcopy(value)
    return L3Input.from_mapping(deepcopy(value))


def _bounded_html(scan_input: L3Input, runtime: RuntimeConfig) -> None:
    """외부 제공 HTML에도 수집기와 같은 크기 제한을 적용한다.

    잘린 사실을 오류 목록과 ``truncated`` 플래그에 모두 남긴다. 이후 Analyzer는
    이 정보를 사용해 관측 부재를 ``detected=False``로 확정하지 않는다.
    """
    content = scan_input.html.content
    if content is None:
        return
    encoded = content.encode(scan_input.html.encoding or "utf-8", errors="replace")
    if len(encoded) <= runtime.max_html_bytes:
        return
    limited = encoded[: runtime.max_html_bytes]
    scan_input.html.content = limited.decode(
        scan_input.html.encoding or "utf-8", errors="replace"
    )
    scan_input.html.truncated = True
    scan_input.collection_errors.append(
        {
            "stage": "input_validation",
            "code": "html_input_limit_exceeded",
            "message": "Provided HTML exceeded the configured analysis limit and was truncated.",
            "details": {"size": len(encoded), "limit": runtime.max_html_bytes},
        }
    )


def _scripts_from_html(html_raw: Mapping[str, Any]) -> list[ScriptInput]:
    """한 번의 HTML 파싱에서 추출한 스크립트 메타데이터를 입력 모델로 변환한다."""
    return [ScriptInput.from_mapping(item) for item in html_raw.get("scripts", [])]


def _mark_external_script_limit(script: ScriptInput, limit: int) -> None:
    """수집 개수 제한을 넘은 외부 스크립트에 구조화 오류를 기록한다."""
    script.collection_errors.append(
        {
            "stage": "script_collection",
            "code": "external_script_limit_exceeded",
            "message": "External script was not fetched because the resource limit was reached.",
            "details": {"limit": limit},
        }
    )


def _prepare_scripts(
    scan_input: L3Input,
    html_raw: Mapping[str, Any],
    runtime: RuntimeConfig,
    *,
    fetch_external_sources: bool,
) -> list[ScriptInput]:
    """제공된 스크립트를 우선하고 URL 스캔에서만 외부 Source를 제한 수집한다.

    Upstream이 제공한 ``scripts``는 이미 확보된 공통 계약이므로 HTML에서 다시
    추출한 목록보다 우선한다. 외부 Source 수집은 ``scan_url`` 진입점이면서 런타임
    정책이 켜진 경우에만 수행하며 개수 제한을 넘은 항목은 URL과 오류만 보존한다.
    """
    # Upstream 스크립트가 있으면 그것을 신뢰한다. HTML-only 입력에서만 공통 HTML
    # 파서가 한 번 추출한 항목을 사용하여 중복 파싱을 피한다.
    scripts = (
        deepcopy(scan_input.scripts)
        if scan_input.scripts
        else _scripts_from_html(html_raw)
    )
    if not fetch_external_sources or not runtime.fetch_external_scripts:
        return scripts

    from urllib.parse import urldefrag

    candidates = [
        script
        for script in scripts
        if script.type == "external"
        and script.source is None
        and (script.media_type or "").split(";", 1)[0].lower()
        in {
            "",
            "module",
            "text/javascript",
            "application/javascript",
            "text/ecmascript",
            "application/ecmascript",
        }
    ]
    fetched: dict[str, ScriptInput] = {}
    selected = []
    duplicates = []
    for script in candidates:
        key = urldefrag(script.source_url or "")[0]
        if key and key in fetched:
            duplicates.append((script, fetched[key]))
            continue
        if len(fetched) >= max(runtime.max_external_scripts, 0):
            _mark_external_script_limit(script, runtime.max_external_scripts)
            continue
        fetched[key or script.script_id] = script
        selected.append(script)
    # Select in document order before starting I/O. Each collector retains its
    # own DNS pinning, redirects, timeout and byte limits. Completion order must
    # not change script order, duplicate relationships, or later JS analysis.
    if len(selected) <= 1:
        for script in selected:
            collect_external_script(script, runtime)
    else:
        with ThreadPoolExecutor(max_workers=min(5, len(selected))) as executor:
            futures = [
                executor.submit(collect_external_script, script, runtime)
                for script in selected
            ]
            for future in futures:
                future.result()
    for script, other in duplicates:
        for attr in [
            "source",
            "sha256",
            "size",
            "truncated",
            "collection_errors",
            "response",
        ]:
            setattr(script, attr, deepcopy(getattr(other, attr)))
    return scripts


def _html_content_for_analysis(scan_input: L3Input) -> str | None:
    """Content-Type 검증 결과에 따라 Parser에 전달할 HTML을 결정한다."""
    content_type = (scan_input.html.content_type or "").split(";", 1)[0].strip().lower()
    has_content_type_error = any(
        error.get("code") == "unsupported_content_type"
        for error in scan_input.collection_errors
    )
    unsupported = (
        content_type not in _HTML_CONTENT_TYPES
        if content_type
        else has_content_type_error
    )
    if not unsupported:
        return scan_input.html.content
    if has_content_type_error:
        return None

    scan_input.collection_errors.append(
        {
            "stage": "input_validation",
            "code": "unsupported_content_type",
            "message": "Input is not an HTML content type.",
            "details": {"content_type": content_type},
        }
    )
    return None


def _collect_errors(
    scan_input: L3Input,
    html_raw: Mapping[str, Any],
    javascript_raw: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """수집·HTML 파싱·JavaScript 분석 오류를 결과의 단일 목록으로 모은다."""
    errors = deepcopy(scan_input.collection_errors)
    errors.extend(deepcopy(html_raw.get("errors", [])))
    errors.extend(deepcopy(javascript_raw.get("errors", [])))
    for script in scan_input.scripts:
        errors.extend(
            {**deepcopy(error), "script_id": script.script_id}
            for error in script.collection_errors
        )
    return errors


class L3Scanner:
    """명세가 요구하는 두 진입점을 제공하는 설정 가능 Scanner.

    ``DetectionPolicy``와 ``RuntimeConfig``의 생명주기를 한 스캔 인스턴스에 묶되,
    탐지 정책과 자원 제한의 책임은 서로 섞지 않는다.
    """

    def __init__(
        self,
        policy: DetectionPolicy | None = None,
        runtime: RuntimeConfig | None = None,
    ) -> None:
        """정책이 생략되면 '미확정 정책'과 안전한 기본 제한을 사용한다."""
        self.policy = policy or DetectionPolicy()
        self.runtime = runtime or RuntimeConfig()

    def scan_content(self, value: L3Input | Mapping[str, Any]) -> dict[str, Any]:
        """제공된 HTML/JavaScript를 네트워크 접근 없이 공통 경로로 분석한다.

        HTML을 한 번 파싱해 공유 Raw를 만든 뒤 JavaScript 정적 분석과 각 Signal
        Analyzer를 실행한다. 개별 Signal의 오류는 전체 결과 조립을 중단하지 않는다.
        """
        return self._scan_content(value, fetch_external_sources=False)

    def _scan_content(
        self,
        value: L3Input | Mapping[str, Any],
        *,
        fetch_external_sources: bool,
    ) -> dict[str, Any]:
        """두 진입점의 공통 파싱·분석 경로를 실행한다."""
        started_at = _now_iso()
        scan_input = _copy_input(value)
        _bounded_html(scan_input, self.runtime)

        html_raw = parse_html(
            _html_content_for_analysis(scan_input),
            scan_input.document_url,
            truncated=scan_input.html.truncated,
        )
        html_raw["credential_classification"] = classify_credential_fields(
            html_raw, self.policy
        )
        scan_input.scripts = _prepare_scripts(
            scan_input,
            html_raw,
            self.runtime,
            fetch_external_sources=fetch_external_sources,
        )
        self._bind_errors(
            scan_input,
            [("page_collection", scan_input.collection_errors, {})]
            + [
                (
                    "script_collection",
                    script.collection_errors,
                    {
                        "script_id": script.script_id,
                        "url": script.source_url or scan_input.document_url,
                    },
                )
                for script in scan_input.scripts
            ],
        )
        javascript_raw = _parse_javascript_with_deferred_gc(
            scan_input,
            html_raw,
            self.policy,
            self.runtime,
        )

        self._bind_errors(
            scan_input,
            [
                ("html_parsing", html_raw.get("errors", []), {}),
                ("javascript_analysis", javascript_raw.get("errors", []), {}),
            ],
        )
        signals = analyze_html(html_raw, scan_input.document_url, self.policy)
        signals.extend(analyze_javascript(javascript_raw, self.policy))
        errors = _collect_errors(scan_input, html_raw, javascript_raw)

        # ``scripts``는 HTML Parser의 내부 전달용 값이며 공개 계약상 JavaScript Raw에
        # 속한다. 같은 메타데이터를 두 트리에 중복 노출하지 않도록 HTML 결과에서 뺀다.
        result_html_raw = deepcopy(html_raw)
        result_html_raw.pop("scripts", None)
        result_html_raw["source"] = scan_input.html.content
        result_html_raw["source_scope"] = (
            "decoded collected HTML, bounded by max_html_bytes; page scripts were not executed"
        )
        finished_at = _now_iso()
        return {
            "schema_version": SCHEMA_VERSION,
            "layer": "L3",
            "target": {
                "original_url": scan_input.original_url,
                "document_url": scan_input.document_url,
                "etld1": etld1(scan_input.document_url),
            },
            "scan": {
                "status": (
                    (
                        "partial"
                        if errors
                        or not javascript_raw["analysis"]["source_complete"]
                        or not html_raw["document"]["source_complete"]
                        else "completed"
                    )
                    if bool(html_raw.get("document", {}).get("parse_succeeded"))
                    else "failed"
                ),
                "policy_name": self.policy.policy_name,
                "observation": {
                    "html_parsed": bool(
                        html_raw.get("document", {}).get("parse_succeeded")
                    ),
                    "html_complete": html_raw.get("document", {}).get(
                        "source_complete"
                    ),
                    "javascript_complete": javascript_raw["analysis"][
                        "source_complete"
                    ],
                    "browser_execution_observed": False,
                    "finished": True,
                },
                "response": scan_input.response,
                "brand_policy": (
                    dict(self.policy.brand_policy_metadata)
                    if self.policy.brand_policy_metadata is not None
                    else None
                ),
                "started_at": started_at,
                "finished_at": finished_at,
            },
            "raw": {"html": result_html_raw, "javascript": javascript_raw},
            "signals": signals,
            "analysis_facts": analyze_native_submission(result_html_raw)
            + analyze_static_data(javascript_raw),
            "errors": errors,
        }

    @staticmethod
    def _bind_errors(scan_input, groups):
        # Bind before copying so one occurrence retains its identity in raw,
        # aggregate errors and impacted analyses. Unrelated targets stay apart.
        for group_index, (stage, errors, target) in enumerate(groups):
            for index, error in enumerate(errors):
                error.setdefault("occurrence_id", f"l3:{stage}:{group_index}:{index}")
                error.setdefault("stage", stage)
                error.setdefault(
                    "impact_scope",
                    "acquisition"
                    if stage in ("page_collection", "script_collection")
                    or error.get("code") == "html_source_truncated"
                    else "analysis",
                )
                error.setdefault("document_url", scan_input.document_url)
                for key, val in target.items():
                    error.setdefault(key, val)

    def scan_snapshot(self, snapshot) -> dict[str, Any]:
        from L3_SCANNER.adapters.page_snapshot import to_l3_input

        return self._scan_content(to_l3_input(snapshot), fetch_external_sources=True)

    def scan_url(self, url: str) -> dict[str, Any]:
        """URL을 안전 제한 아래 수집한 뒤 ``scan_content``의 동일 경로로 분석한다."""
        return self._scan_content(
            collect_page(url, self.runtime), fetch_external_sources=True
        )


def scan_content(
    value: L3Input | Mapping[str, Any],
    policy: DetectionPolicy | None = None,
    runtime: RuntimeConfig | None = None,
) -> dict[str, Any]:
    """일회성 외부 콘텐츠 분석을 위한 편의 함수."""
    return L3Scanner(policy, runtime).scan_content(value)


def scan_url(
    url: str,
    policy: DetectionPolicy | None = None,
    runtime: RuntimeConfig | None = None,
) -> dict[str, Any]:
    """일회성 독립 URL 수집·분석을 위한 편의 함수."""
    return L3Scanner(policy, runtime).scan_url(url)
