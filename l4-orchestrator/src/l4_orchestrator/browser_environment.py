"""Bind the implemented browser Tools to one caller-owned browser context."""
from urllib.parse import urlsplit

from .browser_pages import BrowserPages
from .elements import ElementRegistry
from .network_capture import NetworkCapture
from .network_storage import LocalNetworkStore
from .page_content import PageContentReader
from .page_events import PageEvents
from .page_export_storage import LocalPageExportStore
from .page_state import PageState
from .ports import Authorization
from .screenshot_storage import LocalScreenshotStore
from .sdk_files import FileConnections
from .tools.capture_screenshot import CaptureScreenshotTool
from .tools.check import CheckTool
from .tools.click import ClickTool
from .tools.export_page import ExportPageTool
from .tools.fill import FillTool
from .tools.get_network_requests import GetNetworkRequestsTool
from .tools.get_page_state import GetPageStateTool
from .tools.go_back import GoBackTool
from .tools.hover import HoverTool
from .tools.navigate import NavigateTool
from .tools.press_key import PressKeyTool
from .tools.reload import ReloadTool
from .tools.scroll import ScrollTool
from .tools.select_option import SelectOptionTool
from .tools.wait_for import WaitForTool


class BrowserEnvironment:
    def __init__(self, page, directory, reader, settings):
        self.settings = settings
        self.images = LocalScreenshotStore(directory)
        self.exports = LocalPageExportStore(directory)
        self.records = LocalNetworkStore(directory, reader, max_record_bytes=settings["max_record_bytes"])
        self.captures = []
        self.default = PageState(page, timeout_ms=settings["timeout_ms"])
        # Install Page/response listeners before the first navigation.
        self.pages = BrowserPages(self.default, create_tools=self.create_tools)
        self.files = FileConnections(producers=(self.images, self.exports, self.records),
                                     close_callbacks=(self.close_captures,), screenshots=self.images)

    def create_tools(self, state):
        cfg = self.settings
        elements = ElementRegistry(state, timeout_ms=cfg["timeout_ms"])
        events = PageEvents(state, on_event=lambda event, page: None)
        capture = NetworkCapture(state, page_events=events, save_record=self.records.save,
            max_requests=cfg["max_requests"], max_body_bytes=cfg["max_body_bytes"],
            max_total_body_bytes=cfg["max_total_body_bytes"], capture_timeout_ms=cfg["timeout_ms"],
            response_body_types={"document", "script", "xhr", "fetch"})
        self.captures.append(capture)
        opts = {"timeout_ms": cfg["timeout_ms"], "page_events": events}
        return {
            "get_page_state": GetPageStateTool(state, elements=elements, content=PageContentReader(
                state, timeout_ms=cfg["timeout_ms"], max_text_bytes=cfg["max_text_bytes"],
                max_links=cfg["max_links"], max_links_bytes=cfg["max_links_bytes"])),
            "navigate": NavigateTool(state.page, timeout_ms=cfg["timeout_ms"],
                authorize_url=lambda url: Authorization(urlsplit(url).scheme in {"http", "https"},
                    "HTTP(S) in the caller's isolated investigation network")),
            "click": ClickTool(elements, **opts), "fill": FillTool(elements, **opts),
            "hover": HoverTool(elements, **opts), "check": CheckTool(elements, **opts),
            "select_option": SelectOptionTool(elements, **opts), "press_key": PressKeyTool(elements, **opts),
            "scroll": ScrollTool(state, wait_ms=100,
                reserve_attempt=lambda _: Authorization(True, "Within the running L4 investigation"), **opts),
            "go_back": GoBackTool(state, **opts), "reload": ReloadTool(state, **opts),
            "wait_for": WaitForTool(elements, max_timeout_ms=cfg["timeout_ms"], page_events=events),
            "get_network_requests": GetNetworkRequestsTool(capture, max_return_items=cfg["max_return_items"]),
            "capture_screenshot": CaptureScreenshotTool(state, timeout_ms=cfg["timeout_ms"], save_png=self.images.save_png),
            "export_page": ExportPageTool(state, timeout_ms=cfg["timeout_ms"],
                max_html_bytes=cfg["max_html_bytes"], save_html=self.exports.save_html),
        }

    async def initial_screen(self, job_id, url):
        await self.default.page.goto(url, wait_until="load", timeout=self.settings["timeout_ms"])
        reply = await self.pages.tools["capture_screenshot"].execute({
            "action_id": "initial-screen", "tool": "capture_screenshot", "target": None, "params": {},
            "context": {"job_id": job_id, "scenario_id": "initial-input", "step_id": "initial-screen", "state_id": None},
        })
        if reply["status"] != "success":
            raise RuntimeError("Initial screenshot capture failed: " + str(reply["error"]))
        return reply["result"]

    async def close_captures(self):
        for capture in tuple(self.captures):
            await capture.close()

    async def close(self):
        self.pages.detach()
        await self.close_captures()
