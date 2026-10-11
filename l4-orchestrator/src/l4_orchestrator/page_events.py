"""A caller-owned notification connection for one Page; no tab selection or storage."""
from copy import deepcopy
from datetime import datetime, timezone
import inspect
from typing import Callable

from playwright.async_api import Page

from .page_state import PageState, PageStateError


class PageEvents:
    def __init__(self, state: PageState, *, on_event: Callable[[dict, Page], None]):
        if (not callable(on_event) or inspect.iscoroutinefunction(on_event)
                or inspect.iscoroutinefunction(getattr(on_event, "__call__", None))):
            raise TypeError("on_event must be a synchronous notification/enqueue function")
        if state.page.is_closed():
            raise ValueError("Cannot connect events to a closed Page")
        self.state = state
        self.on_event = on_event
        self.last_delivery_error = None
        self._action_id = None
        self._events = None
        self._closed = False
        state.page.on("framenavigated", self._navigation)
        state.page.on("popup", self._popup)
        state.page.on("close", self.close)

    def _notify(self, kind, page, url):
        event = {"kind": kind, "source_page_id": self.state.page_id, "url": url,
                 "observed_at": datetime.now(timezone.utc).isoformat(),
                 "observed_during_action_id": self._action_id, "delivery_error": None}
        if self._events is not None:
            self._events.append(event)
        try:
            result = self.on_event(deepcopy(event), page)
            if inspect.isawaitable(result):
                if inspect.iscoroutine(result):
                    result.close()
                raise TypeError("The event callback must enqueue work synchronously")
        except Exception:
            # Delivery failure never retries or changes the outcome of browser input.
            event["delivery_error"] = "PAGE_EVENT_DELIVERY_FAILED"
            self.last_delivery_error = deepcopy(event)

    def _navigation(self, frame):
        if frame == self.state.page.main_frame:
            self._notify("navigation", self.state.page, frame.url)

    def _popup(self, popup):
        self._notify("popup", popup, popup.url)

    def begin(self, action_id):
        if self._closed:
            raise PageStateError("INTERNAL_ERROR", "The caller's Page event connection is closed.")
        if self._events is not None:
            raise PageStateError("INTERNAL_ERROR", "Actions on one Page must run serially.")
        self._action_id = action_id
        self._events = []
        return self._events

    def end(self):
        self._action_id = None
        self._events = None

    def close(self, *args):
        if not self._closed:
            self.state.page.remove_listener("framenavigated", self._navigation)
            self.state.page.remove_listener("popup", self._popup)
            self.state.page.remove_listener("close", self.close)
            self._closed = True
