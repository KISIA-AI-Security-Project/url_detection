"""Readback through the backend DTO, with explicit owner isolation."""
import asyncio
from copy import deepcopy
import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import boto3
import pytest

from l4_orchestrator import aws_query
from l4_orchestrator.aws_query import HttpError, owner, read_run
from l4_orchestrator.aws_snapshot import build_snapshot
from l4_orchestrator.storage.aws_reader import AwsRecordReader


def test_actual_aws_readback_reaches_complete_front_snapshot():
    proof = Path(__file__).resolve().parents[2] / "output/l4-aws-runtime-20261006/aws-first-proof"
    rows = json.loads((proof / "ddb-items.json").read_text(encoding="utf-8"))
    final = json.loads((proof / "final-report.json").read_text(encoding="utf-8"))
    request = json.loads((proof / "verification.json").read_text())["request"]

    class ReadbackIO:
        async def query(self, job, prefix, cursor=None):
            assert job == request["job_id"]
            return rows, None

        async def download(self, bucket, key):
            return (proof / "s3-readback" / key.rsplit("/", 1)[1]).read_bytes()

    dto = asyncio.run(build_snapshot(AwsRecordReader(ReadbackIO()),
        {"run_id": request["job_id"], "input": request, "created_at": "test"},
        file_url=lambda row: {"url": "verified-link", "url_expires_at": "test"}))
    assert dto["status"] == dto["store_status"] == "completed"
    assert dto["publish_seq"] == 22
    expected = deepcopy(final)
    for finding, refs in zip(expected["findings"], [[], [], ["artifact://screenshots/0a29e5e94be742768ce0bd41a8741d41"], []]):
        finding["refs"] = refs
    assert dto["result"] == expected
    assert dto["results"] == [{"result_ref": "final", "kind": "final", "data": expected}]
    assert len(dto["files"]) == 16
    assert dto["progress"][0]["text"] == "판단 반환"
    serialized = json.dumps(dto)
    assert "start_token" not in serialized and "body_json" not in serialized and "s3_key" not in serialized
    assert dto["works"] == dto["tasks"] == dto["actions"] == []


def test_actual_rust_snapshot_keeps_report_and_l4_links_without_fast_storage_keys():
    proof = Path(__file__).resolve().parents[2] / "output/l4-aws-runtime-20261006/aws-rust-http-proof"
    rows = json.loads((proof / "actual-ddb-items.json").read_text(encoding="utf-8"))
    final = json.loads((proof / "final-report.json").read_text(encoding="utf-8"))
    original = deepcopy(final)
    before = json.loads((proof / "rust-public-snapshot.json").read_text(encoding="utf-8"))

    class ReadbackIO:
        async def query(self, job, prefix, cursor=None):
            assert job == before["run_id"]
            return rows, None

        async def download(self, bucket, key):
            return (proof / "s3-readback" / key.rsplit("/", 1)[1]).read_bytes()

    dto = asyncio.run(build_snapshot(AwsRecordReader(ReadbackIO()),
        {"run_id": before["run_id"], "input": before["input"], "created_at": "test"},
        file_url=lambda row: {"url": "verified-link", "url_expires_at": "test"}))
    screen_ref = "artifact://screenshots/c63f430ff2aa449c835b697594588f38"
    expected = deepcopy(final)
    for finding, refs in zip(expected["findings"], [[], [screen_ref], [screen_ref], []]):
        finding["refs"] = refs
    assert dto["result"] == expected
    assert dto["results"] == [{"result_ref": "final", "kind": "final", "data": expected}]
    assert dto["status"] == "completed" and dto["publish_seq"] == 30
    assert len(dto["files"]) == 24
    assert {row["file_ref"] for row in dto["files"]} == {row["file_ref"] for row in before["files"]}
    assert "records/" + before["scan_id"] + "/" not in json.dumps(dto)
    assert final == original and final["findings"][0]["refs"]
    assert json.loads((proof / "final-report.json").read_text(encoding="utf-8")) == original


def test_query_authorization_precedes_any_shared_store_read():
    class OwnerLedger:
        def get_item(self, **request):
            assert request["Key"] == {"pk": {"S": "USER#owner-b"}, "sk": {"S": "RUN#run-a"}}
            return {}

    with pytest.raises(HttpError) as failure:
        read_run(OwnerLedger(), "ledger", "owner-b", "run-a")
    assert (failure.value.status, failure.value.code) == (404, "run_not_found")
    with pytest.raises(HttpError) as failure:
        owner({"requestContext": {"authorizer": {"jwt": {"claims": {"sub": "owner-a", "token_use": "id"}}}}})
    assert failure.value.status == 401


def test_worker_error_keeps_store_finalizing_without_fabricating_a_report():
    class Reader:
        async def list_items(self, job, prefix):
            return [{"record_key": "META", "status": "finalizing", "updated_at": "test", "last_saved_seq": 2}]

    dto = asyncio.run(build_snapshot(Reader(),
        {"run_id": "run", "input": {"job_id": "scan"}, "created_at": "test"},
        file_url=None, execution_status="Failed"))
    assert dto["status"] == "failed" and dto["store_status"] == "finalizing"
    assert dto["result"] is None and dto["results"] == []


def test_handler_signs_files_for_the_final_regional_host(monkeypatch):
    """Regression for the real browser S3 redirect/SignatureDoesNotMatch."""
    session = boto3.Session(region_name="ap-northeast-2", aws_access_key_id="offline-test-key",
                            aws_secret_access_key="offline-test-secret")
    monkeypatch.setattr(aws_query.boto3, "Session", lambda **kwargs: session)
    for key, value in {"AWS_REGION": "ap-northeast-2", "L4_TABLE": "test",
                       "L4_BUCKET": "team5-evidence-998301375101-ap-northeast-2-an",
                       "WEB_JOBS_TABLE": "test"}.items():
        monkeypatch.setenv(key, value)

    def inspect_client(event, *, ddb, s3, cfg, web_table):
        return {"url": s3.generate_presigned_url("get_object", Params={"Bucket": cfg.s3_bucket,
                    "Key": "l4/run/test.png", "ResponseContentDisposition": "inline"}, ExpiresIn=900)}

    monkeypatch.setattr(aws_query, "query", inspect_client)
    reply = aws_query.handler({}, None)
    assert reply["statusCode"] == 200
    url = urlsplit(json.loads(reply["body"])["url"])
    params = parse_qs(url.query)
    assert url.hostname == "team5-evidence-998301375101-ap-northeast-2-an.s3.ap-northeast-2.amazonaws.com"
    assert params["X-Amz-Algorithm"] == ["AWS4-HMAC-SHA256"]
    assert params["X-Amz-SignedHeaders"] == ["host"]
    assert params["X-Amz-Expires"] == ["900"]
    assert params["response-content-disposition"] == ["inline"]
