"""독립 URL 수집과 외부 콘텐츠 분석을 연결하는 L3 오케스트레이터.

두 진입점은 수집 이후 반드시 동일한 HTML/JavaScript Parser와 Analyzer 경로를
사용한다. 이 모듈은 결과를 조립하지만 Signal별 탐지 규칙이나 최종 악성/정상 판정을
포함하지 않는다.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from typing import Any, Mapping

from .analyzers.html import analyze_html
from .analyzers.javascript import analyze_javascript
from .collectors.page_collector import collect_external_script, collect_page
from .models.input import L3Input, ScriptInput
from .parsers.html_parser import parse_html
from .parsers.javascript_parser import parse_javascript
from .policies.detection import DetectionPolicy
from .policies.runtime import RuntimeConfig
from .utils.url import etld1

SCHEMA_VERSION = "1.0"
_HTML_CONTENT_TYPES = {"text/html", "application/xhtml+xml"}


def _now_iso() -> str:
    """스캔 메타데이터에 사용할 현재 지역 시각을 초 단위 ISO 문자열로 만든다."""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _copy_input(value: L3Input | Mapping[str, Any]) -> L3Input:
    """호출자가 제공한 입력을 수정하지 않도록 독립된 ``L3Input``을 만든다."""
    if isinstance(value, L3Input):
        return deepcopy(value)
    return L3Input.from_mapping(value)


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


def _prepare_scripts(
    scan_input: L3Input,
    html_raw: Mapping[str, Any],
    runtime: RuntimeConfig,
) -> list[ScriptInput]:
    """제공된 스크립트를 우선하고 필요할 때만 외부 Source를 제한 수집한다.

    Upstream이 제공한 ``scripts``는 이미 확보된 공통 계약이므로 HTML에서 다시
    추출한 목록보다 우선한다. 외부 Source 수집은 런타임 정책이 켜져 있어야 하며
    개수 제한을 넘은 항목은 URL과 오류만 보존한다.
    """
    # Upstream 스크립트가 있으면 그것을 신뢰한다. HTML-only 입력에서만 공통 HTML
    # 파서가 한 번 추출한 항목을 사용하여 중복 파싱을 피한다.
    scripts = (
        deepcopy(scan_input.scripts)
        if scan_input.scripts
        else _scripts_from_html(html_raw)
    )
    external_seen = 0
    for script in scripts:
        if script.type != "external" or script.source is not None:
            continue
        external_seen += 1
        if not runtime.fetch_external_scripts:
            continue
        if external_seen > runtime.max_external_scripts:
            script.collection_errors.append(
                {
                    "stage": "script_collection",
                    "code": "external_script_limit_exceeded",
                    "message": "External script was not fetched because the resource limit was reached.",
                    "details": {"limit": runtime.max_external_scripts},
                }
            )
            continue
        collect_external_script(script, runtime)
    return scripts


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
        errors.extend(deepcopy(script.collection_errors))
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
        started_at = _now_iso()
        scan_input = _copy_input(value)
        _bounded_html(scan_input, self.runtime)

        content_type = (
            (scan_input.html.content_type or "").split(";", 1)[0].strip().lower()
        )
        analyzable_html = scan_input.html.content
        if content_type and content_type not in _HTML_CONTENT_TYPES:
            analyzable_html = None
            if not any(
                error.get("code") == "unsupported_content_type"
                for error in scan_input.collection_errors
            ):
                scan_input.collection_errors.append(
                    {
                        "stage": "input_validation",
                        "code": "unsupported_content_type",
                        "message": "Input is not an HTML content type.",
                        "details": {"content_type": content_type},
                    }
                )
        html_raw = parse_html(
            analyzable_html,
            scan_input.document_url,
            truncated=scan_input.html.truncated,
        )
        scan_input.scripts = _prepare_scripts(scan_input, html_raw, self.runtime)
        javascript_raw = parse_javascript(
            scan_input,
            html_raw,
            self.policy,
            self.runtime,
        )

        signals = analyze_html(html_raw, scan_input.document_url, self.policy)
        signals.extend(analyze_javascript(javascript_raw, self.policy))
        errors = _collect_errors(scan_input, html_raw, javascript_raw)

        # ``scripts``는 HTML Parser의 내부 전달용 값이며 공개 계약상 JavaScript Raw에
        # 속한다. 같은 메타데이터를 두 트리에 중복 노출하지 않도록 HTML 결과에서 뺀다.
        result_html_raw = deepcopy(html_raw)
        result_html_raw.pop("scripts", None)
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
                    "completed"
                    if bool(html_raw.get("document", {}).get("parse_succeeded"))
                    else "failed"
                ),
                "started_at": started_at,
                "finished_at": finished_at,
            },
            "raw": {"html": result_html_raw, "javascript": javascript_raw},
            "signals": signals,
            "errors": errors,
        }

    def scan_url(self, url: str) -> dict[str, Any]:
        """URL을 안전 제한 아래 수집한 뒤 ``scan_content``의 동일 경로로 분석한다."""
        return self.scan_content(collect_page(url, self.runtime))


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
