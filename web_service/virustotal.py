"""Optional VirusTotal URL report lookup. No analysis-module imports."""
from __future__ import annotations
import base64
import json
import os
import re
import time
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener
from .ledger import Ledger

CATEGORIES = ("malicious", "suspicious", "harmless", "undetected", "timeout",
              "confirmed-timeout", "failure", "type-unsupported")
TERMINAL = {"completed", "not_found", "failed", "quota_exhausted"}
SCAN = re.compile(r"^[0-9a-f]{32}$")

def iso(epoch=None):
    return datetime.fromtimestamp(epoch if epoch is not None else time.time(), timezone.utc).isoformat()

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

class ProviderError(Exception):
    def __init__(self, code, retry_after=0):
        self.code, self.retry_after = code, retry_after

class VirusTotal:
    def __init__(self, api_key):
        self.api_key = api_key
        self.opener = build_opener(NoRedirect())

    def lookup(self, url):
        identifier = base64.urlsafe_b64encode(url.encode("utf8")).decode("ascii").rstrip("=")
        request = Request("https://www.virustotal.com/api/v3/urls/" + identifier,
                          headers={"x-apikey": self.api_key, "accept": "application/json"})
        try:
            with self.opener.open(request, timeout=10) as response:
                raw = response.read(2_000_001)
            if len(raw) > 2_000_000:
                raise ProviderError("invalid_response")
            return json.loads(raw)
        except HTTPError as error:
            if error.code == 404:
                raise ProviderError("not_found") from None
            if error.code == 429:
                retry = error.headers.get("Retry-After", "60")
                raise ProviderError("rate_limited", min(900, max(60, int(retry) if retry.isdecimal() else 60))) from None
            if error.code in (401, 403):
                raise ProviderError("provider_access_unavailable") from None
            raise ProviderError("provider_unavailable") from None
        except (URLError, TimeoutError):
            raise ProviderError("provider_unavailable") from None
        except (ValueError, UnicodeError):
            raise ProviderError("invalid_response") from None

def normalize_report(value):
    try:
        data = value["data"]
        attrs = data["attributes"]
        stats = attrs["last_analysis_stats"]
        if data.get("type") != "url" or not isinstance(stats, dict) or not stats:
            raise ValueError()
        normalized = {}
        for category in CATEGORIES:
            count = stats.get(category, 0)
            if type(count) is not int or count < 0:
                raise ValueError()
            normalized[category] = count
        engines = []
        for name, result in (attrs.get("last_analysis_results") or {}).items():
            if not isinstance(name, str) or not isinstance(result, dict):
                raise ValueError()
            category = result.get("category", "undetected")
            if not isinstance(category, str):
                category = "unavailable"
            engines.append({"name": str(result.get("engine_name") or name)[:200],
                            "category": category, "result": str(result.get("result") or "")[:300]})
        engines.sort(key=lambda engine: (
            {"malicious": 0, "suspicious": 1}.get(engine["category"], 2), engine["name"]))
        epoch = attrs.get("last_analysis_date")
        report_at = iso(epoch) if type(epoch) is int and epoch > 0 else None
        identifier = data.get("id", "")
        report_url = ("https://www.virustotal.com/gui/url/" + identifier + "/detection"
                      if isinstance(identifier, str) and re.fullmatch(r"[0-9a-f]{64}", identifier) else None)
        return {"stats": normalized, "engines": engines[:256],
                "report_at": report_at, "report_url": report_url}
    except (KeyError, TypeError, ValueError, OverflowError):
        raise ProviderError("invalid_response") from None

class Worker:
    def __init__(self, ledger, provider):
        self.ledger, self.provider = ledger, provider

    def run(self, event):
        owner, scan, request_id = event["owner_sub"], event["job_id"], event["request_id"]
        item = self.ledger.get(owner, "VT", scan)
        if not item or item.get("request_id") != request_id:
            return {**event, "done": True}
        if item["status"] in TERMINAL:
            return {**event, "done": True}
        job = self.ledger.get(owner, "JOB", scan)
        if not job or item["url"] != job["url"]:
            return {**event, "done": True}
        tries = int(event.get("tries", 0))
        if tries >= 20:
            item.update(status="failed", error="provider_unavailable", checked_at=iso())
            self.ledger.replace(owner, "VT", scan, item, request_id=request_id)
            return {**event, "done": True}
        current = int(time.time())
        stamp = datetime.fromtimestamp(current, timezone.utc)
        quota = self.ledger.reserve_vt_quota(current, stamp.strftime("%Y-%m-%d"), stamp.strftime("%Y-%m"))
        if quota["exhausted"]:
            item.update(status="quota_exhausted", error="quota_exhausted", checked_at=iso())
            self.ledger.replace(owner, "VT", scan, item, request_id=request_id)
            return {**event, "done": True}
        if not quota["allowed"]:
            return {**event, "done": False, "wait_seconds": max(1, quota["wait_seconds"]),
                    "tries": tries}
        try:
            report = normalize_report(self.provider.lookup(item["url"]))
            item.update(status="completed", checked_at=iso(), **report)
        except ProviderError as error:
            if error.code == "rate_limited":
                item.update(status="queued", retry_after=error.retry_after)
                self.ledger.replace(owner, "VT", scan, item, request_id=request_id)
                return {**event, "done": False, "wait_seconds": error.retry_after, "tries": tries + 1}
            status = "not_found" if error.code == "not_found" else "failed"
            item.update(status=status, error=error.code, checked_at=iso())
        self.ledger.replace(owner, "VT", scan, item, request_id=request_id)
        return {**event, "done": True}

_worker = None
def mark_failed(ledger, event):
    owner, scan, request_id = event["owner_sub"], event["job_id"], event["request_id"]
    item = ledger.get(owner, "VT", scan)
    if item and item.get("request_id") == request_id and item.get("status") not in TERMINAL:
        item.update(status="failed", error="provider_unavailable", checked_at=iso())
        ledger.replace(owner, "VT", scan, item, request_id=request_id)
    return {**event, "done": True}

def handler(event, context):
    global _worker
    if event.get("failure"):
        import boto3
        ledger = Ledger(boto3.resource("dynamodb").Table(os.environ["WEB_JOBS_TABLE"]))
        return mark_failed(ledger, event)
    if _worker is None:
        import boto3
        ledger = Ledger(boto3.resource("dynamodb").Table(os.environ["WEB_JOBS_TABLE"]))
        secret = boto3.client("secretsmanager").get_secret_value(SecretId=os.environ["VT_SECRET_ARN"])["SecretString"]
        if secret.startswith("{"):
            secret = json.loads(secret)["api_key"]
        _worker = Worker(ledger, VirusTotal(secret))
    return _worker.run(event)
