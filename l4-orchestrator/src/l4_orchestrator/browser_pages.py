"""Route existing Tool names to caller-created, per-Page Tool instances."""
from dataclasses import replace
from typing import Callable, Mapping

from .page_state import PageState, page_id_for
from .tools.schemas import page_failure


class BrowserPages:
    """One caller-owned BrowserContext; no implicit current tab or page creation.

    create_tools(state) synchronously builds the SAME browser Tool names for each
    Page, with caller-owned limits, URL policy and storage callbacks. It should
    attach network capture there if needed; popup requests before the context's
    page event are not recovered. Non-browser Tools remain registered separately.
    """

    def __init__(self, default_state: PageState, *, create_tools: Callable[[PageState], Mapping]):
        self.default_page_id = default_state.page_id
        self._context = default_state.page.context
        self._timeout_ms = default_state.timeout_ms
        self._create_tools = create_tools
        self._pages, self._failures = {}, {}
        initial = dict(create_tools(default_state))
        if not initial or "get_page_state" not in initial:
            raise ValueError("Per-Page tools must include get_page_state")
        self._ports = {name: tool.as_port() for name, tool in initial.items()}
        self._pages[default_state.page_id] = initial
        self.tools = {name: _PageTool(self, name) for name in initial}
        self._context.on("page", self._register_page)
        for page in self._context.pages:
            self._register_page(page)

    def _register_page(self, page):
        identity = page_id_for(page)
        if identity in self._pages or identity in self._failures or page.is_closed():
            return
        try:
            native = dict(self._create_tools(PageState(page, timeout_ms=self._timeout_ms)))
            if native.keys() != self._ports.keys():
                raise ValueError("Every Page must provide the same browser Tool names")
            self._pages[identity] = native
        except Exception:
            # Event callbacks cannot return a Tool result. Report failed attachment
            # on a later explicit call; never fall back to another Page or retry.
            self._failures[identity] = "The caller's Tool factory could not attach this Page."

    def detach(self):
        """Remove only our discovery listener. The caller still owns resources."""
        self._context.remove_listener("page", self._register_page)


class _PageTool:
    def __init__(self, pages: BrowserPages, name: str):
        self._pages, self._name = pages, name

    async def execute(self, arguments):
        # Reuse the existing native input validation, also for direct execute().
        actual = self._pages._ports[self._name].prepare({"arguments": arguments}, {})
        identity = actual["context"].get("page_id") or self._pages.default_page_id
        if identity in self._pages._failures:
            return page_failure(actual, "PAGE_SETUP_FAILED", self._pages._failures[identity])
        native = self._pages._pages.get(identity)
        if native is None:
            return page_failure(actual, "PAGE_NOT_FOUND", "The page_id does not belong to this browser connection. List open pages again.")
        # Retain a closed Page's tools: the existing HTTP capture remains readable,
        # and action Tools can return their own PAGE_CLOSED result without a retry.
        return await native[self._name].execute(actual)

    def as_port(self):
        original = self._pages._ports[self._name]
        return replace(original, invoke=self.execute,
            description=original.description + " context.page_id selects that Page; omit/null uses the fixed default Page. Discover IDs with get_page_state params.scope=pages.")
