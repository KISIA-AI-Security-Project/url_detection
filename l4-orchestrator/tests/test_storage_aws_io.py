import asyncio
import hashlib

import boto3
from botocore.stub import ANY, Stubber
from botocore.exceptions import ClientError

from l4_orchestrator.storage.aws_codec import AwsStorageConfig, AwsCodec, Upload, typed_item
from l4_orchestrator.storage.aws_io import Boto3StorageIO, classify_aws_error
from l4_orchestrator.storage.aws_reader import AwsRecordReader
from l4_orchestrator.storage.models import CompletedFile, Record, Publication, RetryableWriteError, ConditionalWriteError, PublisherError


def clients():
    config = AwsStorageConfig("ap-northeast-2", "test-l4", "test-evidence")
    session = boto3.Session(aws_access_key_id="stub", aws_secret_access_key="stub")
    io = Boto3StorageIO.from_session(session, config)
    return io, config


def test_botocore_validates_actual_put_transaction_query_and_s3_requests(tmp_path):
    async def case():
        io, config = clients()
        codec = AwsCodec(config, "job", "owner")
        initial = {"job_id": "job", "record_key": "META", "status": "running", "start_token": "owner", "last_saved_seq": 0}
        encoded = codec.encode(Publication(1, (Record.make("RESULT#result:ACT1", {"status": "ok"}, "now"),)))
        request = codec.requests(encoded, last_seq=0, saved_meta=initial)[0]
        db, s3 = Stubber(io.ddb), Stubber(io.s3)
        db.add_response("put_item", {}, {"TableName": config.table_name, "Item": typed_item(initial),
                                          "ConditionExpression": "attribute_not_exists(job_id)"})
        db.add_response("transact_write_items", {}, request.request())
        db.add_response("get_item", {"Item": typed_item(initial)}, {"TableName": config.table_name,
            "Key": typed_item({"job_id": "job", "record_key": "META"}), "ConsistentRead": True})
        cursor = typed_item({"job_id": "job", "record_key": "WORK#W1"})
        query = {"TableName": config.table_name, "ConsistentRead": True,
                 "KeyConditionExpression": "job_id = :job AND begins_with(record_key, :prefix)",
                 "ExpressionAttributeValues": {":job": {"S": "job"}, ":prefix": {"S": "WORK#"}}}
        db.add_response("query", {"Items": [typed_item({"record_key": "WORK#W1"})], "LastEvaluatedKey": cursor}, query)
        db.add_response("query", {"Items": [typed_item({"record_key": "WORK#W2"})]}, query | {"ExclusiveStartKey": cursor})
        db.add_response("query", {"Items": []}, {"TableName": config.table_name, "ConsistentRead": True,
            "KeyConditionExpression": "job_id = :job", "ExpressionAttributeValues": {":job": {"S": "job"}}})
        path = tmp_path / "file"
        raw = b"original file"
        path.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        descriptor = CompletedFile("artifact://existing", path.resolve(), "image/png", len(raw), digest)
        import base64
        s3.add_response("put_object", {}, {"Bucket": config.s3_bucket, "Key": "l4/job/file.png", "Body": ANY,
            "ContentType": "image/png", "ContentLength": len(raw),
            "ChecksumSHA256": base64.b64encode(bytes.fromhex(digest)).decode()})
        with db, s3:
            await io.put_initial_meta(initial)
            await io.transact(request)
            assert await io.get_meta("job") == initial
            assert len(await AwsRecordReader(io).list_items("job", "WORK#")) == 2
            assert await AwsRecordReader(io).list_items("job", "") == []
            await io.upload(Upload("l4/job/file.png", "image/png", len(raw), digest, file=descriptor))
            db.assert_no_pending_responses()
            s3.assert_no_pending_responses()
    asyncio.run(case())


def test_error_classification_does_not_retry_permanent_or_validation_failures():
    def error(code, reasons=None):
        response = {"Error": {"Code": code, "Message": "actual service error"}}
        if reasons is not None:
            response["CancellationReasons"] = [{"Code": reason} for reason in reasons]
        return classify_aws_error(ClientError(response, "TransactWriteItems"))
    assert isinstance(error("ThrottlingException"), RetryableWriteError)
    assert isinstance(error("TransactionCanceledException", ["None", "ConditionalCheckFailed"]), ConditionalWriteError)
    assert isinstance(error("TransactionCanceledException", ["TransactionConflict"]), RetryableWriteError)
    assert type(error("AccessDeniedException")) is PublisherError
    assert type(error("ValidationException")) is PublisherError
    assert type(error("TransactionCanceledException", ["ValidationError"])) is PublisherError
