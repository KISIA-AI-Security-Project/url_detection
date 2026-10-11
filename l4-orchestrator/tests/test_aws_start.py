"""Owned Fast handoff, result-version binding, and one dispatch on repeats."""
from copy import deepcopy
import io
import json
from pathlib import Path
import sys

from botocore.exceptions import ClientError
import pytest

from l4_orchestrator.aws_query import HttpError, worker_key
from l4_orchestrator.aws_start import parse_input, request_key, run_identity, start


WORKSPACE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(WORKSPACE / "evaluation/remediation-20260911/repo"))
INPUT = json.loads((WORKSPACE / "l4-orchestrator/deployment/first-request.json").read_text())
FAST = WORKSPACE / "evaluation/remediation-20261006/public-explanations/new-url-test/aws-final/run-final/case-new-url/s3"


def event(sub="user-a"):
    return {"body": json.dumps(INPUT), "requestContext": {"http": {"method": "POST"},
        "authorizer": {"jwt": {"claims": {"sub": sub, "token_use": "access"}}}}}


class Ledger:
    def __init__(self, race=False):
        self.rows = {("USER#user-a", "JOB#" + INPUT["job_id"]): {"scan_id": {"S": INPUT["job_id"]}}}
        self.race = race

    def get_item(self, **req):
        key = (req["Key"]["pk"]["S"], req["Key"]["sk"]["S"])
        return {"Item": deepcopy(self.rows[key])} if key in self.rows else {}

    def put_item(self, **req):
        item = deepcopy(req["Item"])
        key = (item["pk"]["S"], item["sk"]["S"])
        self.rows[key] = item
        if self.race:
            raise ClientError({"Error": {"Code": "ConditionalCheckFailedException"}}, "PutItem")

    def update_item(self, **req):
        key = (req["Key"]["pk"]["S"], req["Key"]["sk"]["S"])
        self.rows[key]["command_id"] = req["ExpressionAttributeValues"][":command"]


class ActualFastObjects:
    def __init__(self):
        self.requests = {}
        self.reads = 0

    def get_object(self, **req):
        self.reads += 1
        return {"Body": io.BytesIO((FAST / req["Key"]).read_bytes())}

    def put_object(self, **req):
        assert req["IfNoneMatch"] == "*"
        if req["Key"] in self.requests:
            raise ClientError({"Error": {"Code": "PreconditionFailed"}}, "PutObject")
        self.requests[req["Key"]] = req["Body"]


class Dispatcher:
    def __init__(self):
        self.calls = []

    def send_command(self, **req):
        self.calls.append(req)
        return {"Command": {"CommandId": "actual-dispatch-receipt"}}


def invoke(ledger, objects, dispatcher, incoming=None):
    return start(incoming or event(), ddb=ledger, s3=objects, ssm=dispatcher, web_table="web-jobs",
        bucket="team5-evidence-998301375101-ap-northeast-2-an", instance="approved-instance", document="fixed-l4-document")


def test_same_actual_fast_input_dispatches_once_and_preserves_all_identifiers():
    ledger, objects, dispatcher = Ledger(), ActualFastObjects(), Dispatcher()
    first = invoke(ledger, objects, dispatcher)
    second = invoke(ledger, objects, dispatcher)
    assert first["run_id"] == second["run_id"] and first["run_id"] != INPUT["job_id"]
    assert first["reused"] is False and second["reused"] is True
    assert len(dispatcher.calls) == 1
    assert json.loads(objects.requests[request_key(first["run_id"])]) == {"run_id": first["run_id"], "input": INPUT}
    normalized = event()
    normalized["body"] = json.dumps(INPUT | {"attempt": str(INPUT["attempt"])})
    assert run_identity(parse_input(normalized)) == first["run_id"]
    for field in ("attempt", "context_revision", "result_revision"):
        changed = INPUT | {field: 2 if field == "attempt" else "another-accepted-revision"}
        assert run_identity(changed) != first["run_id"]


def test_losing_conditional_owner_run_creation_never_dispatches():
    ledger, objects, dispatcher = Ledger(race=True), ActualFastObjects(), Dispatcher()
    result = invoke(ledger, objects, dispatcher)
    assert result["reused"] is True and dispatcher.calls == []
    assert request_key(result["run_id"]) not in objects.requests


def test_other_owner_cannot_start_from_a_foreign_scan():
    objects, dispatcher = ActualFastObjects(), Dispatcher()
    with pytest.raises(HttpError) as failure:
        invoke(Ledger(), objects, dispatcher, event("user-b"))
    assert failure.value.status == 404
    assert objects.reads == 0 and dispatcher.calls == []


def test_continuous_query_status_exists_before_the_owned_run_becomes_visible():
    ledger, objects, dispatcher = Ledger(), ActualFastObjects(), Dispatcher()
    original_put = ledger.put_item

    def publish_run(**req):
        run_id = req["Item"]["run_id"]["S"]
        assert json.loads(objects.requests[worker_key(run_id)])["execution_status"] == "Pending"
        original_put(**req)

    ledger.put_item = publish_run
    first = invoke(ledger, objects, dispatcher)
    objects.requests[worker_key(first["run_id"])] = b'{"execution_status":"InProgress"}'
    second = invoke(ledger, objects, dispatcher)
    assert second["reused"] is True
    assert json.loads(objects.requests[worker_key(first["run_id"])])["execution_status"] == "InProgress"
