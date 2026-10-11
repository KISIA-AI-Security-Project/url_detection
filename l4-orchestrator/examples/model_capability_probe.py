"""Real gateway/SDK/image/function/structured-output probe; credentials are never saved."""
import argparse
import asyncio
import base64
from hashlib import sha256
import json
from pathlib import Path
from uuid import uuid4
import zipfile

from agents import Agent, ModelSettings, RunConfig, Runner, function_tool
from agents.models.openai_responses import OpenAIResponsesModel
import httpx
from openai import AsyncOpenAI
from playwright.async_api import async_playwright
from pydantic import BaseModel


class ProbeAnswer(BaseModel):
    screen_word: str
    tool_value: str


async def probe(args):
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.credential_zip) as archive:
        options = json.loads(archive.read("opencode (1).json").decode("utf-8-sig"))["provider"]["monorouter-openai"]["options"]
    screen_word, tool_value = "SCREEN_" + uuid4().hex[:8], "TOOL_" + uuid4().hex[:8]
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(channel=args.browser_channel, headless=True)
        try:
            page = await browser.new_page(viewport={"width": 600, "height": 200})
            await page.set_content("<html><body><h1>L4 SDK capability probe</h1><p>" + screen_word + "</p></body></html>")
            png = await page.screenshot(type="png")
        finally:
            await browser.close()
    (out / "screen.png").write_bytes(png)
    requests, responses, calls = [], [], []

    async def record_request(request):
        if request.url.path.endswith("/responses"):
            body = json.loads(await request.aread())
            requests.append(body)
            (out / f"request-{len(requests)}.json").write_text(json.dumps(body, ensure_ascii=False, indent=2), encoding="utf-8")

    async def record_response(response):
        if response.request.url.path.endswith("/responses"):
            raw = await response.aread()
            try:
                value = json.loads(raw)
            except ValueError:
                value = {"http_status": response.status_code}
            responses.append(value)
            (out / f"response-{len(responses)}.json").write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")

    @function_tool
    async def read_probe() -> str:
        """Read the exact locally held probe value; call once before answering."""
        calls.append(tool_value)
        return tool_value

    transport = httpx.AsyncClient(event_hooks={"request": [record_request], "response": [record_response]}, timeout=60)
    async with AsyncOpenAI(api_key=options["apiKey"], base_url=options["baseURL"], http_client=transport) as client:
        agent = Agent(name="L4 capability probe", model=OpenAIResponsesModel(args.model, client),
            instructions="Read the visible SCREEN word from the image. Call read_probe exactly once and copy its returned value. Return both in the specified JSON.",
            tools=[read_probe], output_type=ProbeAnswer,
            model_settings=ModelSettings(reasoning={"effort": "low"}, store=False, parallel_tool_calls=False))
        result = await Runner.run(agent, [{"role": "user", "content": [
            {"type": "input_text", "text": "Verify the visible word and the tool value."},
            {"type": "input_image", "image_url": "data:image/png;base64," + base64.b64encode(png).decode("ascii"), "detail": "auto"}]}],
            max_turns=3, run_config=RunConfig(tracing_disabled=True))
    assert result.final_output.screen_word == screen_word
    assert result.final_output.tool_value == tool_value and calls == [tool_value]
    wire_images = [part["image_url"] for item in requests[0]["input"] if item.get("role") == "user"
                   for part in item.get("content", []) if part.get("type") == "input_image"]
    assert len(wire_images) == 1 and base64.b64decode(wire_images[0].split(",", 1)[1]) == png
    summary = {"model": args.model, "endpoint": options["baseURL"], "model_requests": len(requests),
        "tool_calls": len(calls), "image_sha256": sha256(png).hexdigest(),
        "image_verified": True, "tool_output_verified": True, "structured_output_verified": True,
        "final_output": result.final_output.model_dump(), "usage": result.context_wrapper.usage.__dict__}
    (out / "verification.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, default=str))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--credential-zip", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--browser-channel")
    asyncio.run(probe(parser.parse_args()))
