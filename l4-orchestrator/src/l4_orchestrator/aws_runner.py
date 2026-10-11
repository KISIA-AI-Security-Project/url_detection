"""Trusted AWS entry: stored Fast input, initial pixels, real SDK, and readback."""
import argparse
import asyncio
import base64
from hashlib import sha256
import importlib.metadata
import json
import os
from pathlib import Path
from time import perf_counter

from agents import ModelSettings, RunConfig
from agents.models.openai_responses import OpenAIResponsesModel
import boto3
import httpx
from openai import AsyncOpenAI
from playwright.async_api import async_playwright

from .browser_environment import BrowserEnvironment
from .remote_bash import RemoteBash
from .sdk_registry import register_native_tools, store_reader_binding
from .sdk_runtime import run_l4
from .sdk_types import ExecutionLimits
from .storage.aws_codec import AwsStorageConfig
from .storage.aws_io import Boto3StorageIO
from .storage.aws_publisher import AwsPublisher
from .storage.aws_reader import AwsRecordReader
from .storage.store import L4Store
from .tools.record_reader import RecordReader, RecordSource


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def prepare_fast_input(request, fast_store, inputs, reader):
    # The deployed upstream adapter validates explicit job/attempt/revisions.
    from evidence_pipeline.aws_fast_result import keys, load_deep_input
    prepared = load_deep_input(request, fast_store)
    paths = keys(request["job_id"], str(request["attempt"]))
    context_raw = fast_store.get_bytes(paths["context"])
    context_path = inputs / "context.json"
    context_path.write_bytes(context_raw)
    reader.register("fast:context", RecordSource(context_path, sha256(context_raw).hexdigest()))
    first = prepared["initial_findings"]
    catalog = [{"record_ref": "fast:context", "description": "Builder item/fact to original record mapping",
                "pointers": {"item_mapping": "/item_mapping", "source_mapping": "/source_mapping",
                             "detail_facts": "/details/facts", "detail_sections": "/details/sections"}}]
    allowed_prefixes = (f"raw/{request['job_id']}/{request['attempt']}/",
                        f"records/{request['job_id']}/{request['attempt']}/")
    for layer, artifact in first["source_mapping"]["artifacts"].items():
        for kind in ("raw", "record"):
            key = artifact[kind]
            if not key.startswith(allowed_prefixes):
                raise ValueError("Mapped artifact is outside this Fast attempt")
            raw = fast_store.get_bytes(key)
            if sha256(raw).hexdigest() != artifact[kind + "_sha256"]:
                raise ValueError("Mapped artifact checksum differs from the Builder source")
            path = inputs / f"{layer}-{kind}.json"
            path.write_bytes(raw)
            reader.register(key, RecordSource(path, artifact[kind + "_sha256"]))
            catalog.append({"record_ref": key, "layer": layer, "kind": kind,
                            "root_pointer": artifact[kind + "_root_pointer"]})
    # Preserve the final model body exactly. Detailed records and the complete
    # mapping are queryable, rather than duplicating them in the first prompt.
    prepared["initial_findings"] = {k: first[k] for k in
                                    ("requested_url", "builder_context", "attempt", "context_revision")}
    prepared["initial_findings"]["record_catalog"] = catalog
    return prepared


class WireEvidence:
    def __init__(self, directory):
        self.directory = directory
        self.requests = []
        self.responses = []

    async def request(self, request):
        if request.url.path.endswith("/responses"):
            body = json.loads(await request.aread())
            index = len(self.requests) + 1
            request.extensions["l4_evidence_index"] = index
            self.requests.append(body)
            write_json(self.directory / f"request-{index}.json", body)

    async def response(self, response):
        if response.request.url.path.endswith("/responses"):
            raw = await response.aread()
            index = response.request.extensions["l4_evidence_index"]
            try:
                value = json.loads(raw)
            except ValueError:
                value = {"http_status": response.status_code, "body": raw.decode("utf-8", errors="replace")}
            self.responses.append(value)
            write_json(self.directory / f"response-{index}.json", value)


async def execute(args):
    started = perf_counter()
    cfg = json.loads(args.config.read_text(encoding="utf-8"))
    request = json.loads(args.request.read_text(encoding="utf-8"))
    run_id = args.run_id or request["job_id"]
    out = args.work.resolve()
    inputs, artifacts, wire_dir = (out / name for name in ("inputs", "artifacts", "model-wire"))
    for path in (inputs, artifacts, wire_dir):
        path.mkdir(parents=True, exist_ok=True)
    session = boto3.Session(region_name=cfg["region"])
    if session.client("sts").get_caller_identity()["Account"] != "998301375101":
        raise RuntimeError("Unexpected AWS account")
    storage_cfg = AwsStorageConfig(**{k: cfg[k] for k in ("region", "table_name", "s3_bucket", "s3_prefix")})
    io = Boto3StorageIO.from_session(session, storage_cfg)
    if await io.get_meta(run_id) is not None:
        raise RuntimeError("This L4 job already exists; the runner will not start a second charged analysis")
    from evidence_pipeline.aws_runtime import Store as FastStore
    fast_store = FastStore(session.client("s3"), cfg["s3_bucket"])
    reader = RecordReader({}, max_data_bytes=cfg["tool_settings"]["max_read_bytes"])
    prepared = await asyncio.to_thread(prepare_fast_input, request, fast_store, inputs, reader)
    # The original Fast identifiers stay in the request and catalog. Store
    # ownership belongs to this distinct L4 run, including on Fast reanalysis.
    prepared["job_id"] = run_id
    write_json(out / "prepared-input.json", prepared)
    write_json(out / "source-input.json", request)
    # The key is read only into this trusted process, never into an image, Tool
    # environment, model payload, command line, or diagnostic output.
    secret_reply = session.client("secretsmanager").get_secret_value(SecretId=cfg["credential_secret"])
    credential = json.loads(secret_reply["SecretString"])
    if credential["base_url"] != "https://monogpt.kr/api/monorouter/v1/openai/v1":
        raise RuntimeError("Unexpected model gateway")
    wire = WireEvidence(wire_dir)
    transport = httpx.AsyncClient(trust_env=False, timeout=240,
                                 event_hooks={"request": [wire.request], "response": [wire.response]})
    async with AsyncOpenAI(api_key=credential["api_key"], base_url=credential["base_url"],
                           http_client=transport, max_retries=0) as model_client:
        manager_model = OpenAIResponsesModel(cfg["manager_model"], model_client)
        executor_model = OpenAIResponsesModel(cfg["executor_model"], model_client)
        run_config = RunConfig(tracing_disabled=True,
            model_settings=ModelSettings(reasoning={"effort": cfg["reasoning_effort"]}, store=False))
        store = L4Store(prepared["job_id"])
        publisher = AwsPublisher(store, io, storage_cfg)
        async with async_playwright() as pw:
            browser = await pw.chromium.connect(os.environ["L4_BROWSER_WS"], timeout=30000)
            context = await browser.new_context(service_workers="block", accept_downloads=False)
            env = None
            try:
                page = await context.new_page()
                env = BrowserEnvironment(page, artifacts, reader, cfg["tool_settings"])
                image = await env.initial_screen(prepared["job_id"], prepared["initial_findings"]["requested_url"])
                write_json(out / "initial-screen.json", image)
                png = await env.images.load_png(image["artifact_ref"], image["sha256"])
                native = dict(env.pages.tools)
                native["record_reader"] = reader
                tool_cfg = cfg["tool_settings"]
                native["bash"] = RemoteBash(os.environ["L4_BASH_ENDPOINT"],
                    max_timeout_ms=tool_cfg["bash_max_timeout_ms"], cleanup_timeout_ms=tool_cfg["bash_cleanup_timeout_ms"])
                registry = register_native_tools(native).replacing(store_reader_binding(store,
                    max_list_items=tool_cfg["max_list_items"], max_data_bytes=tool_cfg["max_read_bytes"]))
                write_json(out / "runtime-settings.json", cfg)
                final = await run_l4(**prepared, store=store, publisher=publisher, registry=registry,
                    model_name=manager_model, executor_model=executor_model,
                    execution_limits=ExecutionLimits(**cfg["execution_limits"]),
                    files=env.files, run_config=run_config, initial_screenshot=image)
            finally:
                if env is not None:
                    await env.close()
                await context.close()
                await browser.close()
    readback = AwsRecordReader(io)
    rows = await readback.list_items(store.job_id, "")
    bodies = {}
    verified_files = []
    initial_file_verified = False
    for row in rows:
        if row["record_key"].startswith("FILE#"):
            raw = await readback.file_bytes(row)
            verified_files.append({"record_key": row["record_key"], "size_bytes": len(raw), "sha256": sha256(raw).hexdigest()})
            if row["record_key"] == "FILE#" + image["artifact_ref"]:
                initial_file_verified = raw == png
        elif row["record_key"] != "META":
            bodies[row["record_key"]] = await readback.body(row)
    meta = next(row for row in rows if row["record_key"] == "META")
    first_parts = [part for item in wire.requests[0]["input"] if item.get("role") == "user"
                   for part in item.get("content", [])]
    first_text = json.loads(next(part["text"] for part in first_parts if part["type"] == "input_text"))
    wire_png = base64.b64decode(next(part["image_url"] for part in first_parts if part["type"] == "input_image").split(",", 1)[1])
    checks = {
        "builder_body_unchanged": first_text["initial_findings"]["builder_context"] == prepared["initial_findings"]["builder_context"],
        "previous_judgment_unchanged": first_text["previous_judgment"] == prepared["previous_judgment"],
        "request_text_unchanged": first_text.get("request_text", "") == prepared.get("request_text", ""),
        "initial_png_sent": wire_png == png,
        "initial_png_s3_readback": initial_file_verified,
        "all_model_settings_match": all(body["model"] == cfg["manager_model"] and
            body.get("reasoning", {}).get("effort") == cfg["reasoning_effort"] for body in wire.requests),
        "ddb_completed": meta["status"] == "completed",
        "final_s3_or_ddb_readback": bodies["RESULT#final"] == final.model_dump(mode="json"),
    }
    write_json(out / "ddb-items.json", rows)
    write_json(out / "record-bodies.json", bodies)
    write_json(out / "final-report.json", final.model_dump(mode="json"))
    summary = {"job_id": store.job_id, "request": request, "checks": checks,
        "model_requests": len(wire.requests), "action_records": sum(k.startswith("ACTION#") for k in bodies),
        "manager_records": sum(k.startswith("MANAGER#") for k in bodies),
        "task_records": sum(k.startswith("TASK#") for k in bodies), "published_items": len(rows),
        "verified_files": verified_files, "initial_png_sha256": image["sha256"],
        "builder_body_bytes": len(prepared["initial_findings"]["builder_context"].encode("utf-8")),
        "versions": {name: importlib.metadata.version(name) for name in ("openai-agents", "openai", "playwright", "boto3", "pydantic")},
        "duration_seconds": round(perf_counter() - started, 3)}
    write_json(out / "verification.json", summary)
    print(json.dumps({k: v for k, v in summary.items() if k != "verified_files"}, ensure_ascii=True))
    if not all(checks.values()):
        raise RuntimeError("AWS readback verification did not pass")
    return summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--run-id")
    args = parser.parse_args()
    try:
        asyncio.run(execute(args))
    except Exception as exc:
        # Model/provider exceptions may include payload text. Keep full local
        # traceback out of public worker logs; the wire evidence has no headers.
        args.work.mkdir(parents=True, exist_ok=True)
        write_json(args.work / "run-error.json", {"kind": type(exc).__name__, "message": str(exc)})
        print(json.dumps({"l4_error": type(exc).__name__}, ensure_ascii=True))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
