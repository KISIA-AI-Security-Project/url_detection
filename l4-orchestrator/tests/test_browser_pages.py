"""Actual per-Page routing, captured files, and SDK model-input boundaries."""
import asyncio
from contextlib import asynccontextmanager
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest
from pydantic import ValidationError
from playwright.async_api import async_playwright

from l4_orchestrator.browser_pages import BrowserPages
from l4_orchestrator.elements import ElementRegistry
from l4_orchestrator.network_capture import NetworkCapture
from l4_orchestrator.network_storage import LocalNetworkStore
from l4_orchestrator.page_events import PageEvents
from l4_orchestrator.page_export_storage import LocalPageExportStore
from l4_orchestrator.page_state import PageState, page_id_for
from l4_orchestrator.ports import Authorization
from l4_orchestrator.screenshot_storage import LocalScreenshotStore
from l4_orchestrator.tools.capture_screenshot import CaptureScreenshotTool
from l4_orchestrator.tools.check import CheckTool
from l4_orchestrator.tools.click import ClickTool
from l4_orchestrator.tools.export_page import ExportPageTool
from l4_orchestrator.tools.fill import FillTool
from l4_orchestrator.tools.get_network_requests import GetNetworkRequestsTool
from l4_orchestrator.page_content import PageContentReader
from l4_orchestrator.tools.get_page_state import GetPageStateInput, GetPageStateTool
from l4_orchestrator.tools.go_back import GoBackTool
from l4_orchestrator.tools.hover import HoverTool
from l4_orchestrator.tools.navigate import NavigateTool
from l4_orchestrator.tools.press_key import PressKeyTool
from l4_orchestrator.tools.record_reader import RecordReader
from l4_orchestrator.tools.reload import ReloadTool
from l4_orchestrator.tools.scroll import ScrollTool
from l4_orchestrator.tools.select_option import SelectOptionTool
from l4_orchestrator.tools.wait_for import WaitForTool


@pytest.fixture(scope="module")
def tabs_site():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            raw = ("<!doctype html><title>" + self.path + "</title>" + """
                <body style="min-height:2000px"><h1>""" + self.path + """</h1>
                <button onclick="window.open('/popup')">Open</button>
                <button onclick="window.clicks++;document.querySelector('output').textContent=window.clicks">Count</button>
                <output>0</output><form onsubmit="event.preventDefault()"><input type="email" aria-label="Email"></form>
                <input type="checkbox" aria-label="Consent"><select aria-label="Choice"><option value="one">One</option>
                <option value="two">Two</option></select><script>window.clicks=0</script>""").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()
    thread.join()


def request(name, *, page_id=None, state_id=None, params=None, target=None):
    context = {"job_id": "tabs-local", "scenario_id": "tabs", "step_id": name, "state_id": state_id}
    if page_id is not None:
        context["page_id"] = page_id
    return {"action_id": "test-" + name, "tool": name, "target": target, "params": params or {}, "context": context}


class Environment:
    def __init__(self, page, site, directory):
        self.site = site
        self.reader = RecordReader({}, max_data_bytes=50000)
        self.images = LocalScreenshotStore(directory)
        self.exports = LocalPageExportStore(directory)
        self.records = LocalNetworkStore(directory, self.reader, max_record_bytes=50000)
        self.states, self.native, self.captures = {}, {}, {}
        self.events = []
        self.default = PageState(page, timeout_ms=3000)
        self.pages = BrowserPages(self.default, create_tools=self.create_tools)

    def create_tools(self, state):
        self.states[state.page_id] = state
        elements = ElementRegistry(state, timeout_ms=3000)
        events = PageEvents(state, on_event=lambda event, page: self.events.append(event))
        capture = NetworkCapture(state, page_events=events, save_record=self.records.save,
            max_requests=50, max_body_bytes=10000, max_total_body_bytes=100000,
            capture_timeout_ms=3000, response_body_types={"document"})
        self.captures[state.page_id] = capture
        opts = {"timeout_ms": 3000, "page_events": events}
        native = {
            "get_page_state": GetPageStateTool(state, elements=elements, content=PageContentReader(
                state, timeout_ms=3000, max_text_bytes=10000, max_links=20, max_links_bytes=10000)),
            "navigate": NavigateTool(state.page, timeout_ms=3000, authorize_url=lambda url:
                                     Authorization(url.startswith(self.site + "/"), "local pages only")),
            "click": ClickTool(elements, **opts), "fill": FillTool(elements, **opts),
            "hover": HoverTool(elements, **opts), "check": CheckTool(elements, **opts),
            "select_option": SelectOptionTool(elements, **opts), "press_key": PressKeyTool(elements, **opts),
            "scroll": ScrollTool(state, wait_ms=0, reserve_attempt=lambda _: Authorization(True, "test"), **opts),
            "go_back": GoBackTool(state, **opts), "reload": ReloadTool(state, **opts),
            "wait_for": WaitForTool(elements, max_timeout_ms=3000, page_events=events),
            "get_network_requests": GetNetworkRequestsTool(capture, max_return_items=50),
            "capture_screenshot": CaptureScreenshotTool(state, timeout_ms=3000, save_png=self.images.save_png),
            "export_page": ExportPageTool(state, timeout_ms=3000, max_html_bytes=20000, save_html=self.exports.save_html),
        }
        self.native[state.page_id] = native
        return native

    async def call(self, name, **kwargs):
        return await self.pages.tools[name].execute(request(name, **kwargs))

    async def query(self, identity):
        reply = await self.call("get_page_state", page_id=identity, params={"include": ["elements"]})
        assert reply["status"] == "success", reply
        return reply["result"]

    async def close_captures(self):
        for capture in tuple(self.captures.values()):
            await capture.close()


@asynccontextmanager
async def environment(site, directory):
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(channel=os.environ.get("L4_BROWSER_CHANNEL"), headless=True)
        context = await browser.new_context(service_workers="block", accept_downloads=False)
        await context.route("**/*", lambda route: route.continue_() if route.request.url.startswith(site + "/") else route.abort())
        page = await context.new_page()
        env = Environment(page, site, directory)
        try:
            await page.goto(site + "/a")
            await page.evaluate("() => new Promise(requestAnimationFrame)")
            yield env, page
        finally:
            env.pages.detach()
            await env.close_captures()
            await browser.close()


def element(snapshot, name):
    return next(item["element_id"] for item in snapshot["elements"] if item["name"] == name)


def test_popup_list_select_and_per_page_state_are_real(tabs_site, tmp_path):
    async def check():
        async with environment(tabs_site, tmp_path) as (env, page):
            await page.context.add_cookies([{"name": "session", "value": "kept", "url": tabs_site}])
            a = env.default.page_id
            initial = await env.query(a)
            async with page.expect_popup() as opened:
                clicked = await env.call("click", page_id=a, state_id=initial["state_id"],
                                         target={"element_id": element(initial, "Open")})
            assert clicked["result"]["clicked"] is True
            popup = await opened.value
            await popup.wait_for_load_state("load")
            await popup.evaluate("() => new Promise(requestAnimationFrame)")
            held_a = await env.query(a)
            listing = await env.call("get_page_state", params={"scope": "pages"})
            b = next(p["page_id"] for p in listing["result"]["pages"] if p["url"] == tabs_site + "/popup")
            assert b != a and listing["after_state_id"] is None
            assert listing["result"]["default_page_id"] == a
            held_b = await env.query(b)
            wrong = await env.call("click", page_id=b, state_id=held_a["state_id"],
                                   target={"element_id": element(held_b, "Count")})
            assert wrong["error"]["code"] == "TARGET_STALE"
            assert await popup.evaluate("window.clicks") == 0
            right = await env.call("click", page_id=b, state_id=held_b["state_id"],
                                   target={"element_id": element(held_b, "Count")})
            assert right["result"]["clicked"] is True
            assert await popup.evaluate("window.clicks") == 1 and await page.evaluate("window.clicks") == 0
            assert env.default.read(held_a["state_id"])["page_id"] == a
            assert await popup.evaluate("document.cookie") == "session=kept"
            # Neither explicit B access nor listing changes the omitted-page target.
            default = await env.call("get_page_state", state_id=held_a["state_id"])
            assert default["result"]["page_id"] == a
            again = await env.call("get_page_state", params={"scope": "pages"})
            assert [p["page_id"] for p in again["result"]["pages"]] == [a, b]
            assert env.default.read()["state_id"] == held_a["state_id"]
            (tmp_path / "popup-evidence.json").write_text(json.dumps({
                "listing": listing, "wrong_state": wrong, "action_on_b": right,
                "default_after_b": default, "counts": {"a": 0, "b": 1},
                "cookie_on_b": await popup.evaluate("document.cookie")}, ensure_ascii=False, indent=2), encoding="utf-8")
    asyncio.run(check())


def test_all_native_tools_reject_another_page_before_side_effects(tabs_site, tmp_path):
    async def check():
        async with environment(tabs_site, tmp_path) as (env, page):
            other = await page.context.new_page()
            b = page_id_for(other)
            options = {
                "navigate": ({"url": tabs_site + "/b"}, {}),
                "fill": ({"element_id": "unused"}, {"value_type": "dummy_email"}),
                "scroll": (None, {"direction": "down", "amount": 100.0}),
                "select_option": ({"element_id": "unused"}, {"value": "two"}),
                "press_key": ({"element_id": "unused"}, {"key": "Enter"}),
                "wait_for": (None, {"condition": "timeout", "timeout_ms": 1}),
                "get_network_requests": (None, {"limit": 10}),
                "get_page_state": (None, {"include": ["text", "links", "elements"]}),
            }
            for name, tool in env.native[env.default.page_id].items():
                target, params = options.get(name, ({"element_id": "unused"} if name in {"click", "hover", "check"} else None, {}))
                reply = await tool.execute(request(name, page_id=b, params=params, target=target))
                assert reply["error"]["code"] == "PAGE_MISMATCH", (name, reply)
            assert len(env.native[env.default.page_id]) == 15
            assert page.url == tabs_site + "/a" and other.url == "about:blank"
            assert not env.images.completed_files() and not env.exports.completed_files()
            assert page_id_for(page) == env.default.page_id
    asyncio.run(check())


def test_routed_actions_and_saved_materials_use_b(tabs_site, tmp_path):
    async def check():
        async with environment(tabs_site, tmp_path) as (env, page):
            b_page = await page.context.new_page()
            await b_page.evaluate("() => new Promise(requestAnimationFrame)")
            b = page_id_for(b_page)
            held_a = await env.query(env.default.page_id)
            for path in ("/b", "/b-next"):
                assert (await env.call("navigate", page_id=b, target={"url": tabs_site + path}))["status"] == "success"
            await env.query(b)
            back = await env.call("go_back", page_id=b)
            assert back["status"] == "success", back
            assert b_page.url == tabs_site + "/b"
            await env.query(b)
            reloaded = await env.call("reload", page_id=b)
            assert reloaded["status"] == "success", reloaded
            for name, label, params in [("fill", "Email", {"value_type": "dummy_email"}),
                ("press_key", "Email", {"key": "Enter"}), ("check", "Consent", {}),
                ("select_option", "Choice", {"value": "two"}), ("hover", "Count", {})]:
                observed = await env.query(b)
                result = await env.call(name, page_id=b, state_id=observed["state_id"],
                                        target={"element_id": element(observed, label)}, params=params)
                assert result["status"] == "success", (name, result)
            assert await b_page.locator("input[type=email]").input_value() == "l4-test@example.com"
            assert await b_page.locator("input[type=checkbox]").is_checked()
            assert await b_page.locator("select").input_value() == "two"
            assert await page.locator("input[type=email]").input_value() == ""
            assert not await page.locator("input[type=checkbox]").is_checked()
            observed = await env.query(b)
            assert (await env.call("scroll", page_id=b, state_id=observed["state_id"],
                                   params={"direction": "down", "amount": 200.0}))["status"] == "success"
            assert await b_page.evaluate("scrollY") > 0 and await page.evaluate("scrollY") == 0
            assert (await env.call("wait_for", page_id=b, params={"condition": "load_state", "timeout_ms": 1000}))["status"] == "success"
            content = await env.call("get_page_state", page_id=b, params={"include": ["text", "links"]})
            image = await env.call("capture_screenshot", page_id=b)
            exported = await env.call("export_page", page_id=b)
            for reply in (content, image, exported):
                assert reply["status"] == "success", reply
                assert reply["result"]["page_id"] == b
            html = (tmp_path / exported["result"]["relative_path"]).read_text(encoding="utf-8")
            assert "<title>/b</title>" in html and "<title>/a</title>" not in html
            await env.close_captures()
            await b_page.close()
            network = await env.call("get_network_requests", page_id=b, params={"limit": 50})
            assert network["status"] == "success" and network["result"]["page_id"] == b
            assert all(item["url"].startswith(tabs_site + "/b") for item in network["result"]["requests"])
            assert any(item["detail_state"] == "saved" for item in network["result"]["requests"])
            assert env.default.read(held_a["state_id"])["page_id"] == env.default.page_id
            (tmp_path / "materials-evidence.json").write_text(json.dumps({"content": content,
                "screenshot": image, "export": exported, "closed_page_network": network}, indent=2), encoding="utf-8")
    asyncio.run(check())


def test_closed_default_unknown_id_and_failed_factory_do_not_fall_back(tabs_site, tmp_path):
    async def check():
        async with environment(tabs_site, tmp_path) as (env, page):
            b_page = await page.context.new_page()
            await b_page.goto(tabs_site + "/b")
            await b_page.evaluate("() => new Promise(requestAnimationFrame)")
            b = page_id_for(b_page)
            await page.close()
            listing = await env.call("get_page_state", params={"scope": "pages"})
            assert [p["page_id"] for p in listing["result"]["pages"]] == [b]
            assert (await env.call("get_page_state"))["error"]["code"] == "PAGE_CLOSED"
            assert (await env.call("get_page_state", page_id=b))["result"]["title"] == "/b"
            assert (await env.call("navigate", page_id="missing", target={"url": tabs_site + "/unexpected"}))["error"]["code"] == "PAGE_NOT_FOUND"
            def fail(state):
                raise RuntimeError("Caller attachment failed")
            env.pages._create_tools = fail
            unattached = await b_page.context.new_page()
            failure = await env.call("navigate", page_id=page_id_for(unattached), target={"url": tabs_site + "/unexpected"})
            assert failure["error"]["code"] == "PAGE_SETUP_FAILED"
            assert b_page.url == tabs_site + "/b" and unattached.url == "about:blank"
    asyncio.run(check())


def test_listing_does_not_masquerade_as_a_page_observation():
    for fields in ({"state_id": "state_old"}, {"page_id": "page_old"}):
        with pytest.raises(ValidationError):
            GetPageStateInput.model_validate(request("get_page_state", params={"scope": "pages"}, **fields))
    old = request("get_page_state")
    assert GetPageStateInput.model_validate(old).model_dump(mode="json") == old


def test_sdk_executor_uses_listed_page_and_preserves_actual_input(tabs_site, tmp_path):
    from l4_orchestrator.sdk_files import FileConnections
    from l4_orchestrator.sdk_registry import register_native_tools, store_reader_binding
    from test_sdk_runtime import ScriptModel, execute, report, review, setup, task, tool_call, turn, work

    def last(call):
        output = [i for i in call["input"] if i.get("type") == "function_call_output"][-1]["output"]
        return json.loads(output)["data"]

    def args(params=None, *, page_id=None, state_id=None, target=None):
        context = {"state_id": state_id}
        if page_id is not None:
            context["page_id"] = page_id
        return {"target": target, "params": params or {}, "context": context}

    async def check():
        async with environment(tabs_site, tmp_path) as (env, page):
            b_page = await page.context.new_page()
            await b_page.goto(tabs_site + "/b")
            await b_page.evaluate("() => new Promise(requestAnimationFrame)")
            store, _, io, publisher = setup()
            registry = register_native_tools({**env.pages.tools, "record_reader": env.reader}).replacing(
                store_reader_binding(store, max_list_items=10, max_data_bytes=50000))
            allowed = ["get_page_state", "click"]
            assigned = task(execution={"kind": "agent", "instruction": "목록에서 /b 탭을 찾아 Count 한 번 클릭",
                                      "allowed_tools": allowed, "input_refs": []})
            manager = ScriptModel(turn(works=[work(allowed)], tasks=[assigned], review=review("T1")),
                                  turn(finish=report("report:T1")))
            selected = {}
            def choose(call):
                selected["listing"] = last(call)
                selected["id"] = next(p["page_id"] for p in last(call)["result"]["pages"] if p["url"] == tabs_site + "/b")
                selected["query_input"] = args({"include": ["text", "links", "elements"]}, page_id=selected["id"])
                return tool_call("get_page_state", selected["query_input"], "observe-b")
            def click(call):
                selected["query_reply"] = last(call)
                observed = last(call)["result"]
                assert observed["page_id"] == selected["id"] and observed["title"] == "/b"
                assert "/b" in observed["text"] and observed["links"] == []
                assert observed["links_total"] == 0 and observed["links_truncated"] is False
                selected["click_input"] = args(page_id=selected["id"], state_id=observed["state_id"],
                                                target={"element_id": element(observed, "Count")})
                return tool_call("click", selected["click_input"], "click-b")
            def finish(call):
                selected["reply"] = last(call)
                assert selected["reply"]["result"]["clicked"] is True
                return report("result:ACT3")
            executor = ScriptModel(tool_call("get_page_state", args({"scope": "pages"}), "list-pages"), choose, click, finish)
            await execute(manager, executor, setup_values=(store, registry, io, publisher),
                          files=FileConnections(producers=(env.records,), close_callbacks=(env.close_captures,)))
            assert await b_page.evaluate("window.clicks") == 1 and await page.evaluate("window.clicks") == 0
            actions = [r.body() for r in store.snapshot_records() if r.record_key.startswith("ACTION#")]
            query_actual = json.loads(actions[1]["prepared_input_json"])
            assert actions[1]["tool_name"] == "get_page_state"
            assert json.loads(actions[1]["arguments_json"]) == selected["query_input"]
            assert query_actual["params"] == selected["query_input"]["params"]
            assert query_actual["context"]["page_id"] == selected["id"]
            assert await store.read_result("result:ACT2") == selected["query_reply"]
            actual = json.loads(actions[2]["prepared_input_json"])
            assert actual["context"]["page_id"] == selected["id"] == page_id_for(b_page)
            assert actual["context"]["state_id"] == selected["click_input"]["context"]["state_id"]
            assert actual["target"] == selected["click_input"]["target"]
            assert await store.read_result("result:ACT3") == selected["reply"]
            (tmp_path / "sdk-pages-evidence.json").write_text(json.dumps({**selected, "prepared_input": actual,
                "query_prepared_input": query_actual, "executor_input_after_query": executor.calls[2]["input"],
                "next_executor_input": executor.calls[-1]["input"], "next_manager_input": manager.calls[-1]["input"]},
                ensure_ascii=False, indent=2), encoding="utf-8")
    asyncio.run(check())
