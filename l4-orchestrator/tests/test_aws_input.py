"""Use the actual handed-off Fast attempt, including all original artifacts."""
import json
import asyncio
import os
from pathlib import Path
import sys

from playwright.async_api import async_playwright
from test_browser_pages import tabs_site

from l4_orchestrator.aws_runner import prepare_fast_input
from l4_orchestrator.browser_environment import BrowserEnvironment
from l4_orchestrator.sdk_registry import register_native_tools, store_reader_binding
from l4_orchestrator.storage.store import L4Store
from l4_orchestrator.tools.record_reader import RecordReader


def test_actual_fast_handoff_preserves_model_body_and_queryable_sources(tmp_path, monkeypatch):
    workspace = Path(__file__).resolve().parents[2]
    monkeypatch.syspath_prepend(str(workspace / "evaluation/remediation-20260911/repo"))
    root = workspace / "evaluation/remediation-20261006/public-explanations/new-url-test/aws-final/run-final/case-new-url/s3"
    request = json.loads((workspace / "l4-orchestrator/deployment/first-request.json").read_text())
    prefix = root / f"records/{request['job_id']}/{request['attempt']}/fast"
    context = json.loads((prefix / "context.json").read_bytes())
    judgment = json.loads((prefix / "judgment.json").read_bytes())

    class StoredFast:
        def get_bytes(self, key, optional=False):
            return (root / key).read_bytes()

        def get(self, key, optional=False):
            return json.loads(self.get_bytes(key, optional))

    reader = RecordReader({}, max_data_bytes=524288)
    prepared = prepare_fast_input(request, StoredFast(), tmp_path, reader)
    assert prepared["initial_findings"]["builder_context"] == context["model_body"]
    assert len(context["model_body"].encode("utf-8")) == 28093
    assert prepared["previous_judgment"] == judgment["response"]
    assert "confirmed_facts" not in prepared["initial_findings"]
    assert "source_mapping" not in prepared["initial_findings"]
    for item in prepared["initial_findings"]["record_catalog"]:
        if item["record_ref"] == "fast:context":
            pointer = "/item_mapping/0"
            expected = context["item_mapping"][0]
        else:
            pointer = item["root_pointer"]
            expected = json.loads((root / item["record_ref"]).read_bytes())
            if pointer:
                expected = expected["evidence_record"]
        reply = reader.read({"record_ref": item["record_ref"], "pointer": pointer})
        assert reply["status"] == "ok", reply["error"]
        assert reply["data"] == expected


def test_aws_browser_factory_captures_first_screen_and_registers_page_tools(tabs_site, tmp_path):
    workspace = Path(__file__).resolve().parents[2]
    cfg = json.loads((workspace / "l4-orchestrator/deployment/runtime-config.json").read_text())
    async def check():
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(channel=os.environ.get("L4_BROWSER_CHANNEL"), headless=True)
            context = await browser.new_context()
            env = BrowserEnvironment(await context.new_page(), tmp_path, RecordReader({}, max_data_bytes=524288), cfg["tool_settings"])
            try:
                image = await env.initial_screen("factory-check", tabs_site + "/initial")
                png = await env.images.load_png(image["artifact_ref"], image["sha256"])
                assert png.startswith(b"\x89PNG")
                assert env.default.page.url == tabs_site + "/initial"
                registry = register_native_tools(env.pages.tools).replacing(store_reader_binding(
                    L4Store("factory-check"), max_list_items=200, max_data_bytes=524288))
                assert len(registry.catalog()) == 16
                assert len(env.captures) == 1
                result = await env.pages.tools["get_page_state"].execute({"action_id":"factory-query",
                    "tool":"get_page_state","target":None,"params":{"include":["text","elements"]},
                    "context":{"job_id":"factory-check","scenario_id":"test","step_id":"factory-query","state_id":None}})
                assert result["status"] == "success"
                assert result["result"]["page_id"] == image["page_id"]
            finally:
                await env.close()
                await context.close()
                await browser.close()
    asyncio.run(check())
