"""탐지 정책과 분리된 수집·파싱 자원 제한 설정."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    """신뢰할 수 없는 페이지를 유한한 비용으로 처리하기 위한 상한.

    이 값들은 Signal의 의미를 결정하지 않는다. 특히 외부 스크립트는 명시적으로
    ``fetch_external_scripts``를 활성화한 경우에만 제한적으로 수집한다.
    """

    request_timeout_seconds: float = 10.0
    max_redirects: int = 5
    max_html_bytes: int = 2_000_000
    max_script_bytes: int = 1_000_000
    max_external_scripts: int = 20
    fetch_external_scripts: bool = False
    max_javascript_events: int = 10_000
