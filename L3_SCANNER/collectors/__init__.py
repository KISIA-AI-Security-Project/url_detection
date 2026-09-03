"""네트워크·크기·시간 제한을 적용하는 L3 Collector 패키지."""

from .javascript_collector import collect_external_script
from .page_collector import collect_page

__all__ = ["collect_external_script", "collect_page"]
