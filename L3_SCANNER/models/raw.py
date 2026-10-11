"""명세의 공유 Raw Observation 구조를 만드는 팩토리.

Raw는 관측 사실만 담고 악성/정상 또는 Signal의 최종 판정을 담지 않는다. 모든
키를 초기에 만들어 Parser와 Analyzer 사이의 계약을 안정적으로 유지한다.
"""

from __future__ import annotations

from typing import Any


def empty_html_raw() -> dict[str, Any]:
    """HTML Parser가 채울 표준 Raw 컨테이너를 생성한다."""
    return {
        "document": {},
        "forms": [],
        "inputs": [],
        "buttons": [],
        "images": [],
        "favicon": None,
        "open_graph": {},
        "meta_refresh": None,
        "base": None,
        "errors": [],
    }


def empty_javascript_raw() -> dict[str, Any]:
    """JavaScript 정적 분석기가 채울 표준 이벤트 컨테이너를 생성한다."""
    return {
        "scripts": [],
        "dynamic_execution": [],
        "decode_operations": [],
        "script_injection": [],
        "network_requests": [],
        "dom_access": [],
        "credential_access": [],
        "redirects": [],
        "environment_access": [],
        "branches": [],
        "execution_trace": [],
        "errors": [],
    }
