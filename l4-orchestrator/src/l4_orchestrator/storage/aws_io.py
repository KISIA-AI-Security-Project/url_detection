"""Boto3 I/O. Only fixed values cross the thread boundary."""
import asyncio
import base64
import hashlib

from .aws_codec import plain_item, typed_item
from .models import ConditionalWriteError, PublisherError, RetryableWriteError

RETRY_CODES = {"ProvisionedThroughputExceededException", "ThrottlingException",
               "Throttling", "RequestLimitExceeded", "InternalServerError",
               "InternalError", "ServiceUnavailable", "SlowDown",
               "RequestTimeout", "RequestTimeoutException", "TransactionInProgressException"}


def classify_aws_error(exc):
    from botocore.exceptions import (ClientError, EndpointConnectionError,
        ConnectionClosedError, ReadTimeoutError, ConnectTimeoutError)
    if isinstance(exc, (EndpointConnectionError, ConnectionClosedError, ReadTimeoutError, ConnectTimeoutError)):
        return RetryableWriteError(str(exc))
    if isinstance(exc, ClientError):
        response = exc.response
        code = response.get("Error", {}).get("Code")
        if code == "ConditionalCheckFailedException":
            return ConditionalWriteError(str(exc))
        if code == "TransactionCanceledException":
            reasons = {r.get("Code") for r in response.get("CancellationReasons", [])} - {None, "None"}
            if "ConditionalCheckFailed" in reasons:
                return ConditionalWriteError(str(exc))
            if reasons and reasons <= {"TransactionConflict", "ProvisionedThroughputExceeded", "ThrottlingError"}:
                return RetryableWriteError(str(exc))
        if code in RETRY_CODES or response.get("ResponseMetadata", {}).get("HTTPStatusCode", 0) >= 500:
            return RetryableWriteError(str(exc))
    return PublisherError(str(exc))


class Boto3StorageIO:
    def __init__(self, dynamodb, s3, config):
        self.ddb, self.s3, self.config = dynamodb, s3, config

    @classmethod
    def from_session(cls, session, config):
        from botocore.config import Config
        sdk = Config(connect_timeout=config.connect_timeout, read_timeout=config.read_timeout,
                     retries={"mode": "standard", "total_max_attempts": 1})
        return cls(session.client("dynamodb", region_name=config.region, config=sdk),
                   session.client("s3", region_name=config.region, config=sdk), config)

    async def _call(self, fn):
        async def operation():
            try:
                return await asyncio.to_thread(fn)
            except Exception as exc:
                if isinstance(exc, PublisherError):
                    raise
                raise classify_aws_error(exc) from exc
        task = asyncio.create_task(operation())
        interrupted = None
        while True:
            try:
                result = await asyncio.shield(task)
                break
            except asyncio.CancelledError as exc:
                if task.cancelled():
                    raise
                interrupted = interrupted or exc
        if interrupted is not None:
            raise interrupted
        return result

    async def put_initial_meta(self, meta):
        request = {"TableName": self.config.table_name, "Item": typed_item(meta),
                   "ConditionExpression": "attribute_not_exists(job_id)"}
        await self._call(lambda: self.ddb.put_item(**request))

    async def get_meta(self, job_id):
        return await self.get_item(job_id, "META")

    async def get_item(self, job_id, record_key):
        request = {"TableName": self.config.table_name,
                   "Key": typed_item({"job_id": job_id, "record_key": record_key}), "ConsistentRead": True}
        reply = await self._call(lambda: self.ddb.get_item(**request))
        return plain_item(reply["Item"]) if "Item" in reply else None

    async def query(self, job_id, prefix, cursor=None):
        request = {"TableName": self.config.table_name, "ConsistentRead": True,
                   "KeyConditionExpression": "job_id = :job",
                   "ExpressionAttributeValues": {":job": {"S": job_id}}}
        if prefix:
            request["KeyConditionExpression"] += " AND begins_with(record_key, :prefix)"
            request["ExpressionAttributeValues"][":prefix"] = {"S": prefix}
        if cursor is not None:
            request["ExclusiveStartKey"] = cursor
        reply = await self._call(lambda: self.ddb.query(**request))
        return [plain_item(i) for i in reply["Items"]], reply.get("LastEvaluatedKey")

    async def transact(self, request):
        payload = request.request()
        await self._call(lambda: self.ddb.transact_write_items(**payload))

    async def upload(self, upload):
        def put():
            if upload.size_bytes > 5 * 1024**3:
                raise PublisherError("File exceeds this publisher's single PutObject limit")
            params = dict(Bucket=self.config.s3_bucket, Key=upload.key,
                          ContentType=upload.content_type, ContentLength=upload.size_bytes,
                          ChecksumSHA256=base64.b64encode(bytes.fromhex(upload.sha256)).decode("ascii"))
            if upload.body is not None:
                if len(upload.body) != upload.size_bytes or hashlib.sha256(upload.body).hexdigest() != upload.sha256:
                    raise PublisherError("JSON upload differs from its fixed checksum")
                return self.s3.put_object(Body=upload.body, **params)
            descriptor = upload.file
            if descriptor is None:
                raise PublisherError("Upload has neither bytes nor a completed file")
            # Hash and upload through the same opened handle. S3 validates the
            # full requested checksum, including a mutation during upload.
            with descriptor.local_path.open("rb") as handle:
                digest, size = hashlib.sha256(), 0
                while block := handle.read(1024 * 1024):
                    digest.update(block)
                    size += len(block)
                if size != upload.size_bytes or digest.hexdigest() != upload.sha256:
                    raise PublisherError("Completed file changed before upload")
                handle.seek(0)
                return self.s3.put_object(Body=handle, **params)
        await self._call(put)

    async def download(self, bucket, key):
        if bucket != self.config.s3_bucket or not key.startswith(self.config.s3_prefix.rstrip("/") + "/"):
            raise PublisherError("Object is outside the configured L4 storage scope")
        def get():
            reply = self.s3.get_object(Bucket=bucket, Key=key)
            with reply["Body"] as stream:
                return stream.read()
        return await self._call(get)
