"""JWT-authenticated web adapter around the unchanged fast-analysis functions."""
from __future__ import annotations
import base64
import json
import os
import re
import time
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from .ledger import Ledger
from evidence_pipeline.model_choices import ModelChoiceError, public_model_choices, select_model
from evidence_pipeline.request_options import normalize_request_text

SCAN = re.compile(r"^[0-9a-f]{32}$")
REVISION = re.compile(r"^[0-9a-f]{64}$")
RUN = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
DONE = {"accepted", "not_requested", "failed", "invalid"}

def now():
    return datetime.now(timezone.utc).isoformat()

class ApiError(Exception):
    def __init__(self, status, code, message):
        self.status, self.code, self.message = status, code, message

def reply(status, body):
    return {"statusCode": status,
            "headers": {"content-type": "application/json; charset=utf-8",
                        "cache-control": "no-store", "x-content-type-options": "nosniff"},
            "body": json.dumps(body, ensure_ascii=False, default=lambda value: int(value))}

def principal(event):
    authorizer = (event.get("requestContext") or {}).get("authorizer") or {}
    claims = (authorizer.get("jwt") or {}).get("claims") or authorizer.get("claims") or {}
    owner = claims.get("sub")
    # Issuer/signature and required scope are verified by the API Gateway authorizer.
    clients = tuple(value for value in (os.environ.get("WEB_CLIENT_ID"),
                                       os.environ.get("WEB_LOGIN_CLIENT_ID")) if value)
    if (not isinstance(owner, str) or not RUN.fullmatch(owner) or claims.get("token_use") != "access"
            or (clients and claims.get("client_id") not in clients)):
        raise ApiError(401, "authentication_required", "로그인 후 이용해 주세요.")
    return owner

def body_json(event):
    raw = event.get("body") or "{}"
    if event.get("isBase64Encoded"):
        try:
            raw = base64.b64decode(raw, validate=True).decode("utf8")
        except (ValueError, UnicodeError):
            raise ApiError(400, "bad_request", "요청 형식을 확인해 주세요.") from None
    if not isinstance(raw, str) or len(raw.encode("utf8")) > 16384:
        raise ApiError(400, "bad_request", "요청 형식을 확인해 주세요.")
    try:
        value = json.loads(raw)
    except (ValueError, TypeError):
        raise ApiError(400, "bad_request", "요청 형식을 확인해 주세요.") from None
    if not isinstance(value, dict):
        raise ApiError(400, "bad_request", "요청 형식을 확인해 주세요.")
    return value

class WebApi:
    def __init__(self, ledger, invoke, start_vt, *, deep_start=None, deep_get=None):
        self.ledger, self.invoke, self.start_vt = ledger, invoke, start_vt
        self.deep_start, self.deep_get = deep_start, deep_get

    def owned(self, owner, scan):
        if not isinstance(scan, str) or not SCAN.fullmatch(scan):
            raise ApiError(400, "invalid_scan_id", "분석 주소를 확인해 주세요.")
        job = self.ledger.get(owner, "JOB", scan)
        if not job:
            raise ApiError(404, "not_found", "이 계정의 분석 결과를 찾을 수 없습니다.")
        return job

    def fast(self, scan):
        status, result = self.invoke("result", {
            "pathParameters": {"scanId": scan},
            "requestContext": {"http": {"method": "GET"}}})
        if status >= 400:
            raise ApiError(status, "analysis_unavailable", "분석 결과를 불러오지 못했습니다.")
        if result.get("schema_version") != "fast-result-1" or result.get("job_id") != scan:
            raise ApiError(502, "unexpected_result", "분석 결과를 표시하지 못했습니다.")
        return result

    def request_vt(self, owner, scan, job):
        previous = self.ledger.get(owner, "VT", scan)
        if previous:
            return self.vt_public(previous)
        if not job.get("virustotal_requested"):
            job = {**job, "virustotal_requested": True}
            self.ledger.replace(owner, "JOB", scan, job)
        request_id = uuid.uuid4().hex
        item = {"schema_version": "virustotal-url-report-1", "status": "queued",
                "source": "VirusTotal", "url": job["url"], "requested_at": now(),
                "request_id": request_id}
        if not self.ledger.put_new(owner, "VT", scan, item):
            return self.vt_public(self.ledger.get(owner, "VT", scan))
        try:
            self.start_vt({"owner_sub": owner, "job_id": scan, "request_id": request_id,
                           "tries": 0})
        except Exception:
            item.update(status="failed", error="start_failed")
            self.ledger.replace(owner, "VT", scan, item, request_id=request_id)
        return self.vt_public(item)

    @staticmethod
    def vt_public(item):
        if not item:
            return {"schema_version": "virustotal-url-report-1", "status": "not_requested",
                    "source": "VirusTotal"}
        fields = ("schema_version", "status", "source", "url", "requested_at", "checked_at",
                  "report_at", "stats", "engines", "report_url", "error", "retry_after")
        return {key: item[key] for key in fields if key in item}

    def submit(self, owner, value):
        if set(value) - {"url", "virustotal", "scanId", "request_id", "model_choice", "reasoning_effort"}:
            raise ApiError(400, "bad_request", "요청 형식을 확인해 주세요.")
        raw_url = value.get("url")
        vt = value.get("virustotal", False)
        request = value.get("request_id")
        if not isinstance(raw_url, str) or not raw_url.strip() or type(vt) is not bool:
            raise ApiError(400, "bad_request", "분석할 웹 주소를 확인해 주세요.")
        if not isinstance(request, str) or not SCAN.fullmatch(request):
            raise ApiError(400, "request_id_required", "분석 요청을 다시 준비해 주세요.")
        selection = None
        if "reasoning_effort" in value and "model_choice" not in value:
            raise ApiError(400, "model_choice_required", "추론 강도를 적용할 분석 모델을 선택해 주세요.")
        if "model_choice" in value:
            try:
                selection = select_model(value["model_choice"], **({"reasoning_effort": value["reasoning_effort"]}
                                         if "reasoning_effort" in value else {}))
            except ModelChoiceError as error:
                unavailable = str(error) in {"model_choices_unavailable", "invalid_model_configuration"}
                raise ApiError(503 if unavailable else 400, str(error),
                               "분석 모델 목록을 다시 확인해 주세요.") from None
        old = self.ledger.get(owner, "REQUEST", request)
        identity = {"url": raw_url.strip(), "virustotal": vt, "scanId": value.get("scanId")}
        if selection is not None:
            identity["model_choice"] = selection["choice"]
            identity["reasoning_effort"] = selection["profile"]["output_effort"]
        if old:
            previous_identity = deepcopy(old.get("input"))
            # Requests accepted before the effort selector already froze their
            # effective effort in the selection profile. Preserve those retries.
            if (isinstance(previous_identity, dict) and "model_choice" in previous_identity
                    and "reasoning_effort" not in previous_identity and old.get("model_selection")):
                previous_identity["reasoning_effort"] = old["model_selection"]["profile"]["output_effort"]
            if previous_identity != identity:
                raise ApiError(409, "request_changed", "이미 사용한 요청 번호입니다.")
            if old.get("response"):
                response = deepcopy(old["response"])
                if selection is not None:
                    response.setdefault("reasoning_effort", old["model_selection"]["profile"]["output_effort"])
                return 202, response
            raise ApiError(409, "request_in_progress", "접수 상태를 확인하고 있습니다. 분석 기록을 확인해 주세요.")
        scan = value.get("scanId")
        if scan is not None:
            previous_job = self.owned(owner, scan)
            if previous_job["url"] != raw_url.strip():
                raise ApiError(409, "rescan_url_changed", "재분석은 같은 웹 주소에 요청해 주세요.")
        intent = {"input": identity, "status": "submitting", "created_at": now()}
        if selection is not None:
            intent["model_selection"] = selection
        if not self.ledger.put_new(owner, "REQUEST", request, intent):
            raise ApiError(409, "request_in_progress", "접수 중인 요청입니다.")
        # VT and owner metadata remain outside Fast. The model profile is resolved
        # by this server and rechecked by Gate before it becomes execution input.
        gate_body = {"url": raw_url.strip()}
        if selection is not None:
            gate_body.update(model_choice=selection["choice"], model_selection=selection)
            if selection["profile"]["output_effort"] is not None:
                gate_body["reasoning_effort"] = selection["profile"]["output_effort"]
        if scan:
            gate_body["scanId"] = scan
        status, accepted = self.invoke("gate", {"body": json.dumps(gate_body),
            "requestContext": {"http": {"method": "POST"}}})
        if status != 202:
            intent.update(status="rejected", response_error=accepted)
            self.ledger.replace(owner, "REQUEST", request, intent)
            raise ApiError(status if status >= 400 else 502,
                           str(accepted.get("error", "analysis_rejected")),
                           accepted.get("reason", "분석 요청을 접수하지 못했습니다."))
        scan = accepted.get("scanId")
        if not isinstance(scan, str) or not SCAN.fullmatch(scan) or accepted.get("pollUrl") != "/analyses/" + scan:
            raise ApiError(502, "unexpected_acceptance", "분석 접수 상태를 확인하지 못했습니다.")
        if selection is not None and (accepted.get("model_choice") != selection["choice"] or
                                     accepted.get("model_profile_sha256") != selection["profile_sha256"] or
                                     accepted.get("reasoning_effort") != selection["profile"]["output_effort"]):
            raise ApiError(502, "model_selection_unconfirmed", "선택한 분석 모델의 접수를 확인하지 못했습니다.")
        job = {"scan_id": scan, "url": raw_url.strip(), "created_at": now(),
               "virustotal_requested": False}
        if selection is not None:
            job["model_choice"] = selection["choice"]
            job["reasoning_effort"] = selection["profile"]["output_effort"]
        if not value.get("scanId"):
            if not self.ledger.put_new(owner, "JOB", scan, job):
                raise ApiError(502, "ownership_conflict", "분석 접수 상태를 확인하지 못했습니다.")
        else:
            job = self.owned(owner, scan)
            # Rescan preserves the job's target; changing it would contradict the original ledger.
            if job["url"] != raw_url.strip():
                raise ApiError(409, "rescan_url_changed", "재분석은 같은 웹 주소에 요청해 주세요.")
        accepted = {**accepted, "pollUrl": "/api/analyses/" + scan, "virustotal": vt}
        if selection is not None:
            accepted["model_choice"] = selection["choice"]
            accepted["reasoning_effort"] = selection["profile"]["output_effort"]
        intent.update(status="accepted", response=deepcopy(accepted))
        self.ledger.replace(owner, "REQUEST", request, intent)
        # Optional lookup has its own POST after this acceptance. No VT I/O can delay Fast.
        return 202, accepted

    def start_deep(self, owner, scan, value):
        self.owned(owner, scan)
        identifiers = {"job_id", "attempt", "context_revision", "result_revision"}
        if not identifiers <= value.keys() or set(value) - identifiers - {"request_text"}:
            raise ApiError(400, "bad_deep_request", "현재 분석 결과에서 다시 요청해 주세요.")
        value = deepcopy(value)
        if "request_text" in value:
            try:
                if type(value["request_text"]) is not str:
                    raise ValueError("invalid_request_text")
                request_text = normalize_request_text(value.pop("request_text"))
            except ValueError:
                raise ApiError(400, "invalid_request_text", "확인하고 싶은 내용을 2,000자 이내로 작성해 주세요.") from None
            if request_text:
                value["request_text"] = request_text
        fast = self.fast(scan)
        if value.get("job_id") != scan or type(value.get("attempt")) is not int:
            raise ApiError(400, "bad_deep_request", "현재 분석 결과에서 다시 요청해 주세요.")
        if any(value.get(key) != fast.get(key) for key in identifiers):
            raise ApiError(409, "result_changed", "빠른 분석 결과가 바뀌었습니다. 최신 결과를 확인해 주세요.")
        if fast["judgment_status"] != "accepted" or not fast["deep_analysis"]["available"]:
            raise ApiError(409, "deep_not_ready", "빠른 분석 완료 후 심층분석을 요청해 주세요.")
        if self.deep_start is None:
            raise ApiError(503, "deep_unavailable", "심층분석 연결을 준비하고 있습니다.")
        # The request text is a separate user interest; it changes no Fast evidence.
        status, accepted = self.deep_start(owner, value)
        if status not in (200, 202):
            raise ApiError(status, "deep_start_failed", accepted.get("message", "심층분석을 시작하지 못했습니다."))
        run_id = accepted.get("run_id")
        if not isinstance(run_id, str) or not RUN.fullmatch(run_id):
            raise ApiError(502, "unexpected_deep_run", "심층분석 접수 상태를 확인하지 못했습니다.")
        # L4 start owns atomic creation/reuse of RUN; the web boundary only verifies it.
        if not self.ledger.get(owner, "RUN", run_id):
            raise ApiError(502, "deep_ownership_unconfirmed", "심층분석 접수 상태를 확인하지 못했습니다.")
        return status, {**accepted, "poll_url": "/api/deep/" + run_id,
                        "events_url": "/api/deep/" + run_id + "/events"}

    def handle(self, event):
        owner = principal(event)
        method = (event.get("requestContext", {}).get("http") or {}).get("method") or event.get("httpMethod")
        path = event.get("rawPath") or event.get("path") or ""
        if method == "GET" and path == "/api/analysis-models":
            try:
                return reply(200, public_model_choices())
            except ModelChoiceError as error:
                raise ApiError(503, str(error), "분석 모델 목록을 불러오지 못했습니다.") from None
        if method == "GET" and path == "/api/analyses":
            return reply(200, {"analyses": self.ledger.jobs(owner)})
        if method == "POST" and path == "/api/analyses":
            status, value = self.submit(owner, body_json(event))
            return reply(status, value)
        match = re.fullmatch(r"/api/analyses/([0-9a-f]{32})(/virustotal|/deep)?", path)
        if match:
            scan, suffix = match.groups()
            job = self.owned(owner, scan)
            if suffix is None and method == "GET":
                return reply(200, self.fast(scan))
            if suffix == "/virustotal" and method == "GET":
                return reply(200, self.vt_public(self.ledger.get(owner, "VT", scan)))
            if suffix == "/virustotal" and method == "POST":
                return reply(202, self.request_vt(owner, scan, job))
            if suffix == "/deep" and method == "POST":
                status, value = self.start_deep(owner, scan, body_json(event))
                return reply(status, value)
        match = re.fullmatch(r"/api/deep/([A-Za-z0-9_-]{1,128})", path)
        if match and method == "GET":
            run_id = match.group(1)
            if not self.ledger.get(owner, "RUN", run_id):
                raise ApiError(404, "not_found", "이 계정의 심층분석을 찾을 수 없습니다.")
            if self.deep_get is None:
                raise ApiError(503, "deep_unavailable", "심층분석 연결을 준비하고 있습니다.")
            status, value = self.deep_get(owner, run_id)
            return reply(status, value)
        raise ApiError(404, "not_found", "요청한 기능을 찾을 수 없습니다.")

def runtime():
    import boto3
    from botocore.config import Config
    sdk = Config(connect_timeout=3, read_timeout=25, retries={"total_max_attempts": 1})
    lam = boto3.client("lambda", config=sdk)
    ledger = Ledger(boto3.resource("dynamodb").Table(os.environ["WEB_JOBS_TABLE"]))
    functions = {"gate": os.environ["FAST_GATE_ARN"], "result": os.environ["FAST_RESULT_ARN"]}
    def invoke_arn(arn, event):
        response = lam.invoke(FunctionName=arn, InvocationType="RequestResponse",
                              Payload=json.dumps(event).encode())
        payload = response["Payload"]
        try:
            value = json.loads(payload.read())
        finally:
            payload.close()
        if response.get("FunctionError"):
            raise ApiError(502, "service_unavailable", "서비스 응답을 받지 못했습니다.")
        return int(value["statusCode"]), json.loads(value["body"])
    def invoke(role, event):
        return invoke_arn(functions[role], event)
    sf = boto3.client("stepfunctions", config=sdk)
    def start_vt(event):
        sf.start_execution(stateMachineArn=os.environ["VT_STATE_MACHINE_ARN"],
                           name="vt-" + event["request_id"], input=json.dumps(event))
    start_arn, query_arn = os.environ.get("DEEP_START_ARN"), os.environ.get("DEEP_QUERY_ARN")
    def deep_start(owner, value):
        return invoke_arn(start_arn, {"body": json.dumps(value, ensure_ascii=False),
            "requestContext": {"authorizer": {"jwt": {"claims": {"sub": owner, "token_use": "access"}}},
                               "http": {"method": "POST"}}})
    def deep_get(owner, run_id):
        return invoke_arn(query_arn, {"pathParameters": {"runId": run_id},
            "requestContext": {"authorizer": {"jwt": {"claims": {"sub": owner, "token_use": "access"}}},
                               "http": {"method": "GET"}}})
    return WebApi(ledger, invoke, start_vt,
                  deep_start=deep_start if start_arn else None,
                  deep_get=deep_get if query_arn else None)

_app = None
def handler(event, context):
    global _app
    try:
        if _app is None:
            _app = runtime()
        return _app.handle(event)
    except ApiError as error:
        return reply(error.status, {"error": error.code, "message": error.message})
    except Exception:
        # Do not expose provider credentials, source data or raw SDK exceptions.
        return reply(503, {"error": "service_unavailable", "message": "잠시 후 다시 이용해 주세요."})
