"""In-memory identities for supported elements on one caller-owned Page."""
import asyncio
from datetime import datetime, timezone
import hashlib
from importlib.resources import files
from uuid import uuid4

from playwright.async_api import Error

from .page_state import PageState, PageStateError


_SCRIPT = files("l4_orchestrator").joinpath("_browser/elements.js").read_text(encoding="utf-8")


class ElementRegistry:
    """The caller serializes page actions, state refreshes and element queries."""

    def __init__(self, state: PageState, *, timeout_ms: int):
        if type(timeout_ms) is not int or timeout_ms < 1:
            raise ValueError("timeout_ms must be a positive integer")
        self.state = state
        self.page = state.page
        self.timeout_ms = timeout_ms
        self._handle = None
        self._retired_handle = None
        self._published_ids = set()
        self._state_id = None
        self._wait_handle = None
        self._wait_ids = set()
        self._wait_state_id = None
        self._document_version = 0
        self.page.on("framenavigated", self._on_navigation)
        self.page.on("close", self._reset)
        self.page.on("crash", self._reset)

    def _reset(self, *args):
        # A same-document navigation may keep the JS context alive. Release its
        # old handle on the next query; full navigation/closure releases context.
        self._document_version += 1
        if self._handle is not None:
            self._retired_handle = self._handle
        self._handle = None
        self._published_ids.clear()
        self._state_id = None

    def _on_navigation(self, frame):
        if frame == self.page.main_frame:
            self._reset()

    async def _registry(self):
        if self._retired_handle is not None:
            retired, self._retired_handle = self._retired_handle, None
            await retired.dispose()
        if self._handle is None:
            version = self._document_version
            prefix = "el_" + uuid4().hex
            handle = await self.page.evaluate_handle(
                "() => {" + _SCRIPT + f"\nreturn L4Elements.createRegistry('{prefix}');" + "}")
            if version != self._document_version:
                await handle.dispose()
                raise PageStateError("STATE_CHANGED", "The page navigated while preparing element identities.")
            self._handle = handle
        return self._handle

    def _check_observation(self, snapshot, observed):
        self.state.read(snapshot["state_id"])
        fingerprint = "sha256:" + hashlib.sha256(observed["html"].encode("utf-8")).hexdigest()
        if observed["url"] != snapshot["url"] or fingerprint != snapshot["dom_fingerprint"]:
            self.state.invalidate()
            raise PageStateError("STATE_CHANGED", "The page differs from the supplied observation. Refresh its state.")

    async def _collect(self, snapshot, visible_only):
        handle = await self._registry()
        observed = await handle.evaluate("(registry, visibleOnly) => registry.collect(visibleOnly)", visible_only)
        self._check_observation(snapshot, observed)
        return observed["elements"]

    def discard_query(self):
        """Discard published action/wait IDs without replacing the original nodes."""
        self._published_ids.clear()
        self._state_id = None
        self._wait_handle = None
        self._wait_ids.clear()
        self._wait_state_id = None

    async def query(self, *, visible_only: bool, expected_state_id=None):
        """Inspect controls against a new (null ID) or explicitly pinned state."""
        # A failed query must not leave an earlier list available for actions.
        self.discard_query()
        try:
            snapshot = await self.state.observe(expected_state_id)
            elements = await asyncio.wait_for(
                self._collect(snapshot, visible_only), self.timeout_ms / 1000)
            self._published_ids = {item["element_id"] for item in elements}
            self._state_id = snapshot["state_id"]
            self._wait_handle = self._handle
            self._wait_ids = set(self._published_ids)
            self._wait_state_id = snapshot["state_id"]
            return {
                "elements": elements, "page_id": snapshot["page_id"],
                "state_id": snapshot["state_id"],
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "observation_scope": "main_document_light_dom",
            }
        except TimeoutError as exc:
            self.state._check_page()  # A known close/crash takes precedence over collection timeout.
            raise PageStateError("ACTION_TIMEOUT", "Element observation timed out. No current list is available.") from exc
        except Error as exc:
            # Preserve known close/crash/state-change errors from the state holder.
            self.state.read(expected_state_id)
            raise PageStateError("INTERNAL_ERROR", str(exc)) from exc

    async def resolve(self, element_id: str, *, expected_state_id: str):
        """Return the exact observed node, never a selector that can find a replacement.

        For later action Tools. The caller disposes the returned ElementHandle and
        checks action-specific conditions immediately before acting.
        """
        snapshot = self.state.read(expected_state_id)
        if self._state_id != expected_state_id:
            raise PageStateError("STATE_CHANGED", "The element query does not match this Page's current state.")
        if element_id not in self._published_ids:
            raise PageStateError("ELEMENT_NOT_FOUND", "The element ID is absent from this Page's latest successful query.")

        async def resolve_current():
            bundle = await self._handle.evaluate_handle("""(registry, id) => ({
                node: registry.resolve(id), html: document.documentElement.outerHTML, url: location.href
            })""", element_id)
            node_handle = None
            try:
                observed = await bundle.evaluate("value => ({html: value.html, url: value.url})")
                self._check_observation(snapshot, observed)
                node_handle = await bundle.get_property("node")
                node = node_handle.as_element()
                if node is None or not await node.evaluate("node => node.isConnected && node.getRootNode() === document"):
                    raise PageStateError("STATE_CHANGED", "The observed element was removed or replaced.")
                self.state.read(expected_state_id)
                result = node
                node_handle = None  # Ownership passes to the caller only after validation.
                return result
            finally:
                if node_handle is not None:
                    await node_handle.dispose()
                await bundle.dispose()

        try:
            return await asyncio.wait_for(resolve_current(), self.timeout_ms / 1000)
        except TimeoutError as exc:
            raise PageStateError("ACTION_TIMEOUT", "Resolving the observed element timed out.") from exc
        except Error as exc:
            self.state.read(expected_state_id)
            raise PageStateError("INTERNAL_ERROR", str(exc)) from exc

    async def resolve_for_wait(self, element_id: str, *, expected_state_id: str):
        """Return the registered original node, including a removed node, for waiting.

        DOM changes and same-document URL changes may have invalidated action
        state. This separate path never authorizes input or rematches a node.
        """
        self.state.read_comparison(expected_state_id)
        if self._wait_state_id != expected_state_id or self._wait_handle is None:
            raise PageStateError("STATE_CHANGED", "No element list belongs to this comparison baseline.")
        if element_id not in self._wait_ids:
            raise PageStateError("ELEMENT_NOT_FOUND", "The ID was not registered by the baseline element query.")
        handle = None
        try:
            handle = await self._wait_handle.evaluate_handle(
                "(registry, id) => registry.resolveForWait(id)", element_id)
            self.state.read_comparison(expected_state_id)
            node = handle.as_element()
            if node is None:
                raise PageStateError("STATE_CHANGED", "The original node reference is no longer available.")
            result, handle = node, None  # Caller owns this one handle.
            return result
        except Error as exc:
            self.state._check_page()
            raise PageStateError("STATE_CHANGED", "The original document is no longer available.") from exc
        finally:
            if handle is not None:
                try:
                    await handle.dispose()
                except Error:
                    pass
