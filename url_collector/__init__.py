"""L2와 L3가 같은 HTTP 응답을 공유하도록 하는 공통 수집 패키지."""

from .client import Resolver, collect_url, system_resolver
from .models import PageSnapshot, RedirectHop
from .policy import CollectionPolicy

__all__ = [
    "CollectionPolicy",
    "PageSnapshot",
    "RedirectHop",
    "Resolver",
    "collect_url",
    "system_resolver",
]
