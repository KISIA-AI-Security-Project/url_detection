"""One current observation of one Page, kept only in memory."""
import asyncio
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
from uuid import uuid4
from weakref import WeakKeyDictionary

from playwright.async_api import Error, Page


_PAGE_IDS = WeakKeyDictionary()


def page_id_for(page: Page) -> str:
    """Stable identity of the actual Page, shared by observation and navigation."""
    if page not in _PAGE_IDS:
        _PAGE_IDS[page] = "page_" + uuid4().hex
    return _PAGE_IDS[page]


_COLLECT = """() => {
    const elements = Array.from(document.querySelectorAll('*'));
    const visible = elements.filter(element => {
        const box = element.getBoundingClientRect();
        const visibility = getComputedStyle(element).visibility;
        return box.width > 0 && box.height > 0 && !['hidden', 'collapse'].includes(visibility);
    });
    return {
        url: location.href, title: document.title,
        html: document.documentElement.outerHTML,
        visible_element_count: visible.length,
        form_count: document.forms.length
    };
}"""


class PageStateError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class PageState:
    """Queries can collect a new observation; strict reads never collect."""

    def __init__(self, page: Page, *, timeout_ms: int):
        if type(timeout_ms) is not int or timeout_ms < 1:
            raise ValueError("timeout_ms must be a positive integer")
        self.page = page
        self.page_id = page_id_for(page)
        self.timeout_ms = timeout_ms
        self._value = None
        self._comparison = None  # Latest successful observation; never authorizes input.
        self._crashed = False
        self._failure = ("INTERNAL_ERROR", "No page state has been collected. Call refresh first.")
        self._generation = 0
        self._tracking_task = None
        self._binding = "__l4_invalidate_" + uuid4().hex
        self._watch_script = """(() => {
            if (window !== window.top || window['BINDING_observer']) return;
            const notify = () => window['BINDING']().catch(() => {});
            const observer = new MutationObserver(notify);
            observer.observe(document, {subtree: true, childList: true, attributes: true, characterData: true});
            window['BINDING_observer'] = observer;
            window.addEventListener('resize', notify);
            window.addEventListener('load', notify, true);
        })()""".replace("BINDING", self._binding)
        page.on("framenavigated", self._on_navigation)
        page.on("close", self.invalidate)
        page.on("crash", self._on_crash)

    def invalidate(self, *args):
        self._generation += 1
        self._value = None
        self._failure = ("STATE_CHANGED", "The previous observation is no longer current. Refresh the page state.")

    def _on_navigation(self, frame):
        if frame == self.page.main_frame:
            self.invalidate()

    def _on_crash(self, *args):
        self._crashed = True
        self.invalidate()
        self._failure = ("BROWSER_CRASH", "The observed page crashed.")

    def _on_dom_change(self, source):
        if source["frame"] == self.page.main_frame:
            self.invalidate()

    async def _install_tracking(self):
        await self.page.expose_binding(self._binding, self._on_dom_change)
        await self.page.add_init_script(self._watch_script)

    async def _collect(self):
        if self._tracking_task is None:
            self._tracking_task = asyncio.create_task(self._install_tracking())
            self._tracking_task.add_done_callback(lambda task: task.exception() if not task.cancelled() else None)
        # Registration may already have reached the browser when refresh times out.
        # Keep that one operation and await it again on the next explicit refresh.
        await asyncio.shield(self._tracking_task)
        await self.page.evaluate(self._watch_script)
        generation = self._generation
        observed = await self.page.evaluate(_COLLECT)
        if generation != self._generation:
            raise PageStateError("STATE_CHANGED", "The page changed while collecting its state. Refresh again.")
        return observed, generation

    def _check_page(self):
        if self.page.is_closed():
            raise PageStateError("PAGE_CLOSED", "The supplied page is closed.")
        if self._crashed:
            raise PageStateError("BROWSER_CRASH", "The observed page crashed.")

    async def refresh(self):
        """Replace the last observation. A failed refresh leaves no usable old value."""
        self._check_page()
        self._comparison = None  # Failed/cancelled collection cannot revive an old baseline.
        self.invalidate()
        try:
            observed, generation = await asyncio.wait_for(self._collect(), self.timeout_ms / 1000)
            self._check_page()
            if generation != self._generation:
                raise PageStateError("STATE_CHANGED", "The page changed before the observation could be accepted.")
            html = observed.pop("html")
            self._value = {
                "state_id": "state_" + uuid4().hex, "page_id": self.page_id,
                **observed, "dom_fingerprint": "sha256:" + hashlib.sha256(html.encode("utf-8")).hexdigest(),
                "active": True,  # This instance observes the Page assigned by the caller, not OS focus.
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "observation_scope": "main_document_light_dom",
            }
            self._comparison = self._value
            return self.read()
        except TimeoutError as exc:
            self._check_page()
            self._failure = ("ACTION_TIMEOUT", "Page state collection timed out. No current observation is available.")
            raise PageStateError(*self._failure) from exc
        except Error as exc:
            self._check_page()
            self._failure = ("INTERNAL_ERROR", str(exc))
            raise PageStateError(*self._failure) from exc
        except PageStateError as exc:
            self._check_page()
            self._failure = (exc.code, str(exc))
            raise

    async def observe(self, expected_state_id=None):
        """Null collects once; an explicit ID only reads that valid observation.

        Action Tools use read(), never this method, so stale targets cannot be
        silently replaced by new observations. Collection does not reload a page.
        """
        if expected_state_id is not None:
            return self.read(expected_state_id)
        return await self.refresh()

    def read(self, expected_state_id=None):
        """Read a copy of the latest valid observation without a browser RPC."""
        self._check_page()
        if self._value is None:
            raise PageStateError(*self._failure)
        if expected_state_id is not None and expected_state_id != self._value["state_id"]:
            raise PageStateError("STATE_CHANGED", "The requested state does not match this Page's current observation.")
        return deepcopy(self._value)

    def read_comparison(self, expected_state_id=None):
        """Read the latest observation for waiting, even after input invalidates it.

        This does not collect or restore a usable action state. A new collection
        discards the previous baseline, including when collection fails.
        """
        self._check_page()
        if self._comparison is None:
            raise PageStateError("STATE_CHANGED", "No comparison baseline is available. Query the page first.")
        if expected_state_id is not None and expected_state_id != self._comparison["state_id"]:
            raise PageStateError("STATE_CHANGED", "The requested comparison baseline has been replaced.")
        return deepcopy(self._comparison)
