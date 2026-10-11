"""Validate an owned Fast result and dispatch its one distinct L4 run."""
from datetime import datetime, timezone
from hashlib import sha256
import json
import os

import boto3
from botocore.exceptions import ClientError

from .aws_query import HttpError, owner, read_run, response, worker_key
from .json_values import dumps, loads
from .storage.aws_codec import typed_item


def parse_input(event):
    body = event.get("body")
    if type(body) is not str or len(body.encode("utf-8")) > 16384:
        raise HttpError(400, "invalid_deep_input")
    try:
        value = loads(body)
        required = {"job_id", "attempt", "context_revision", "result_revision"}
        if type(value) is not dict or not required <= set(value) or set(value) - required - {"request_text"}:
            raise ValueError("Explicit Fast identifiers required")
        from evidence_pipeline.aws_runtime import identity
        from evidence_pipeline.request_options import normalize_request_text
        text = normalize_request_text(value.pop('request_text', ''))
        if text:
            value['request_text'] = text
        _, attempt, _ = identity(value, require_url=False)
        value["attempt"] = int(attempt)
        for field in ("context_revision", "result_revision"):
            if type(value[field]) is not str or not value[field] or len(value[field]) > 128:
                raise ValueError("Explicit revision required")
        return value
    except ValueError:
        raise HttpError(400, "invalid_deep_input") from None


def run_identity(value):
    # Same Fast identifiers and same optional focus reuse one run. A different
    # question receives its own run; an omitted/blank focus keeps legacy identity.
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return sha256(canonical.encode("utf-8")).hexdigest()[:32]


def request_key(run_id):
    return "l4/_runtime/" + run_id + "/request.json"


def start(event, *, ddb, s3, ssm, web_table, bucket, instance, document):
    sub = owner(event)
    if event.get("requestContext", {}).get("http", {}).get("method") != "POST":
        raise HttpError(405, "method_not_allowed")
    value = parse_input(event)
    job = ddb.get_item(TableName=web_table,
        Key=typed_item({"pk": "USER#" + sub, "sk": "JOB#" + value["job_id"]}), ConsistentRead=True)
    if "Item" not in job or job["Item"].get("scan_id") != {"S": value["job_id"]}:
        raise HttpError(404, "analysis_not_found")
    run_id = run_identity(value)

    def existing():
        try:
            row = read_run(ddb, web_table, sub, run_id)
        except HttpError as exc:
            if exc.status == 404:
                return None
            raise
        if row["input"] != value:
            raise HttpError(502, "run_binding_invalid")
        return {"run_id": run_id, "scan_id": value["job_id"], "input": value, "reused": True}

    reused = existing()
    if reused is not None:
        return reused
    # Match the current upstream's accepted result and handoff before reserving
    # a run. No Builder or Judgment regeneration and no model call occurs here.
    from evidence_pipeline.aws_fast_result import load_deep_input
    from evidence_pipeline.aws_runtime import PipelineServiceError, Store
    try:
        load_deep_input(value, Store(s3, bucket))
    except PipelineServiceError:
        raise HttpError(409, "deep_input_not_available") from None
    # Continuous query may begin as soon as the owned RUN is visible. Prepare
    # its readable status first; a repeated start must not replace worker state.
    try:
        s3.put_object(Bucket=bucket, Key=worker_key(run_id),
            Body=dumps({"execution_status": "Pending", "updated_at": datetime.now(timezone.utc).isoformat()}).encode(),
            ContentType="application/json; charset=utf-8", IfNoneMatch="*")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "PreconditionFailed":
            raise
    row = {"pk": "USER#" + sub, "sk": "RUN#" + run_id, "run_id": run_id,
           "scan_id": value["job_id"], "input_json": dumps(value),
           "created_at": datetime.now(timezone.utc).isoformat()}
    item = typed_item(row)
    if "ttl" in job["Item"]:
        item["ttl"] = job["Item"]["ttl"]
    try:
        ddb.put_item(TableName=web_table, Item=item,
                     ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ConditionalCheckFailedException":
            raise
        return existing()
    try:
        s3.put_object(Bucket=bucket, Key=request_key(run_id), Body=dumps({"run_id": run_id, "input": value}).encode(),
                      ContentType="application/json; charset=utf-8", IfNoneMatch="*")
        reply = ssm.send_command(InstanceIds=[instance], DocumentName=document,
                                 Parameters={"RunId": [run_id]}, Comment="Requested L4 analysis " + run_id)
    except Exception:
        ddb.update_item(TableName=web_table, Key=typed_item({"pk": row["pk"], "sk": row["sk"]}),
            UpdateExpression="SET dispatch_error = :error", ExpressionAttributeValues={":error": {"S": "dispatch_failed"}})
        raise HttpError(502, "l4_dispatch_failed") from None
    # Dispatch already succeeded. A receipt write must not claim that the
    # process failed; continuous query uses the worker journal and Store.
    try:
        ddb.update_item(TableName=web_table, Key=typed_item({"pk": row["pk"], "sk": row["sk"]}),
            UpdateExpression="SET command_id = :command", ExpressionAttributeValues={":command": {"S": reply["Command"]["CommandId"]}})
    except Exception as exc:
        print(json.dumps({"l4_receipt_error": type(exc).__name__}))
    return {"run_id": run_id, "scan_id": value["job_id"], "input": value, "reused": False}


def handler(event, context):
    try:
        session = boto3.Session(region_name=os.environ["AWS_REGION"])
        result = start(event, ddb=session.client("dynamodb"), s3=session.client("s3"),
            ssm=session.client("ssm"), web_table=os.environ["WEB_JOBS_TABLE"], bucket=os.environ["L4_BUCKET"],
            instance=os.environ["L4_INSTANCE"], document=os.environ["L4_SSM_DOCUMENT"])
        return response(200, result)
    except HttpError as exc:
        return response(exc.status, {"error": {"code": exc.code}})
    except Exception as exc:
        print(json.dumps({"l4_start_error": type(exc).__name__}))
        return response(502, {"error": {"code": "l4_start_failed"}})
