"""명세 Signal별 HTML Analyzer 공개 API."""

from .runner import ANALYZERS, analyze_html

__all__ = ["ANALYZERS", "analyze_html"]
