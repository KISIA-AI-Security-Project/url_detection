"""Explicit local-test limits for the public, unified page query."""
from l4_orchestrator.elements import ElementRegistry
from l4_orchestrator.page_content import PageContentReader
from l4_orchestrator.tools.get_page_state import GetPageStateTool


def make_query_tool(state, *, elements=None, **overrides):
    limits = dict(timeout_ms=3000, max_text_bytes=10000, max_links=20, max_links_bytes=10000)
    content = PageContentReader(state, **{**limits, **overrides})
    if elements is None:
        elements = ElementRegistry(state, timeout_ms=3000)
    return GetPageStateTool(state, elements=elements, content=content)
