"""Internal authenticated-BFF adapter for the backend's continuous reads."""
import asyncio
from datetime import datetime, timedelta, timezone
import json
import os
import re

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from .aws_snapshot import build_snapshot
from .json_values import loads
from .storage.aws_codec import AwsStorageConfig, plain_item, typed_item
from .storage.aws_io import Boto3StorageIO
from .storage.aws_reader import AwsRecordReader


class HttpError(Exception):
    def __init__(self, status, code):
        self.status, self.code = status, code


def owner(event):
    # This function has no public URL. The Cognito-protected BFF forwards its
    # verified access-token claims through an IAM-authorized Lambda invocation.
    claims = event.get("requestContext", {}).get("authorizer", {}).get("jwt", {}).get("claims", {})
    sub = claims.get("sub")
    if claims.get("token_use") != "access" or type(sub) is not str or not sub or len(sub) > 128:
        raise HttpError(401, "authentication_required")
    return sub


def response(status, value):
    return {"statusCode": status, "headers": {"Content-Type": "application/json; charset=utf-8",
            "Cache-Control": "no-store"}, "body": json.dumps(value, ensure_ascii=False, allow_nan=False)}


def read_run(ddb, table, sub, run_id):
    if type(run_id) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", run_id):
        raise HttpError(400, "invalid_run_id")
    reply = ddb.get_item(TableName=table, Key=typed_item({"pk": "USER#" + sub, "sk": "RUN#" + run_id}),
                         ConsistentRead=True)
    if "Item" not in reply:
        raise HttpError(404, "run_not_found")
    row = plain_item(reply["Item"])
    if row["run_id"] != run_id:
        raise HttpError(502, "run_binding_invalid")
    row["input"] = loads(row["input_json"])
    return row


def worker_key(run_id):
    return "l4/_runtime/" + run_id + "/worker-status.json"


def query(event, *, ddb, s3, cfg, web_table):
    sub = owner(event)
    run = read_run(ddb, web_table, sub, event.get("pathParameters", {}).get("runId"))
    execution_status = None
    if run.get("dispatch_error"):
        execution_status = "Failed"
    else:
        try:
            reply = s3.get_object(Bucket=cfg.s3_bucket, Key=worker_key(run["run_id"]))
            with reply["Body"] as stream:
                execution_status = loads(stream.read().decode("utf-8"))["execution_status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in {"NoSuchKey", "404"}:
                raise
    io = Boto3StorageIO(ddb, s3, cfg)

    def file_url(row):
        if row["s3_bucket"] != cfg.s3_bucket or not row["s3_key"].startswith("l4/" + run["run_id"] + "/"):
            raise HttpError(502, "file_binding_invalid")
        # Issued only after owner verification. Files are not made public and
        # the client receives no bucket permissions or local container paths.
        disposition = "inline" if row["content_type"] == "image/png" else "attachment"
        url = s3.generate_presigned_url("get_object", Params={"Bucket": cfg.s3_bucket, "Key": row["s3_key"],
            "ResponseContentDisposition": disposition}, ExpiresIn=900)
        return {"url": url, "url_expires_at": (datetime.now(timezone.utc) + timedelta(seconds=900)).isoformat()}

    return asyncio.run(build_snapshot(AwsRecordReader(io), run, file_url=file_url,
                                      execution_status=execution_status))


def handler(event, context):
    try:
        region = os.environ["AWS_REGION"]
        cfg = AwsStorageConfig(region=region, table_name=os.environ["L4_TABLE"],
                               s3_bucket=os.environ["L4_BUCKET"])
        session = boto3.Session(region_name=region)
        # A presigned Host must match the S3 region; a redirect invalidates it.
        s3 = session.client("s3", endpoint_url=f"https://s3.{region}.amazonaws.com",
                            config=Config(signature_version="s3v4", s3={"addressing_style": "virtual"}))
        value = query(event, ddb=session.client("dynamodb"), s3=s3, cfg=cfg,
                      web_table=os.environ["WEB_JOBS_TABLE"])
        return response(200, value)
    except HttpError as exc:
        return response(exc.status, {"error": {"code": exc.code}})
    except Exception as exc:
        # Never echo provider/model payloads, credentials, or service internals.
        print(json.dumps({"l4_query_error": type(exc).__name__}))
        return response(502, {"error": {"code": "l4_query_failed"}})
