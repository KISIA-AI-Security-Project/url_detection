"""제한형 정적 JavaScript Analyzer의 Mixin 조합 지점."""

from typing import Any

from .expressions import ExpressionMixin
from .observations import ObservationMixin
from .statements import StatementMixin


class StaticAnalyzer(StatementMixin, ExpressionMixin, ObservationMixin):
    """제어문 순회, 표현식 전파, 이벤트 기록 책임을 결합한 분석기."""

    def analyze(self, tree: dict[str, Any]) -> None:
        """ESTree 루트부터 정적 순회를 시작한다."""
        self._process_statement(tree)
