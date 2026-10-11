"""Bounded text/link collector used by the single public page query Tool."""
import asyncio
import hashlib
from importlib.resources import files
from typing import Literal

from playwright.async_api import Error

from .page_state import PageState, PageStateError


_COLLECT = files("l4_orchestrator").joinpath("_browser/page_content.js").read_text(encoding="utf-8")


class PageContentReader:
    def __init__(self, state: PageState, *, timeout_ms: int, max_text_bytes: int,
                 max_links: int, max_links_bytes: int):
        for name, value in (("timeout_ms", timeout_ms), ("max_text_bytes", max_text_bytes),
                            ("max_links", max_links), ("max_links_bytes", max_links_bytes)):
            minimum = 2 if name == "max_links_bytes" else 1
            if type(value) is not int or value < minimum:
                raise ValueError(f"{name} must be an integer >= {minimum}")
        self.state = state
        self.timeout_ms = timeout_ms
        self._limits = {"maxTextBytes": max_text_bytes, "maxLinks": max_links,
                        "maxLinksBytes": max_links_bytes}

    async def _collect(self, snapshot, kind):
        try:
            observed = await self.state.page.evaluate(_COLLECT, {"kind": kind, **self._limits})
            self.state.read(snapshot["state_id"])
            fingerprint = "sha256:" + hashlib.sha256(observed.pop("html").encode("utf-8")).hexdigest()
            if observed["url"] != snapshot["url"] or fingerprint != snapshot["dom_fingerprint"]:
                self.state.invalidate()
                raise PageStateError("STATE_CHANGED", "The page changed while reading its content.")
            return observed
        except Error as exc:
            self.state._check_page()
            self.state.read(snapshot["state_id"])
            raise PageStateError("INTERNAL_ERROR", "The assigned page content could not be read.") from exc
        except UnicodeError as exc:
            raise PageStateError("INVALID_PAGE_TEXT", "The page contains text that cannot be encoded as UTF-8.") from exc

    async def read(self, *, kind: Literal["text", "links", "both"], expected_state_id: str):
        """Read against an already chosen observation; never refresh it here."""
        if kind not in {"text", "links", "both"} or not expected_state_id:
            raise ValueError("Content collection requires a valid kind and an explicit state_id")
        snapshot = self.state.read(expected_state_id)
        try:
            return await asyncio.wait_for(self._collect(snapshot, kind), self.timeout_ms / 1000)
        except TimeoutError as exc:
            self.state._check_page()
            raise PageStateError("ACTION_TIMEOUT", "Page content collection timed out.") from exc
