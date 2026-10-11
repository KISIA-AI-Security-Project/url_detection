"""Frozen Store records to ordered S3 uploads and DynamoDB transactions."""
from dataclasses import dataclass
import hashlib
from urllib.parse import quote
from uuid import uuid4

from ..json_values import dumps, loads
from .models import CompletedFile, Publication, PublishRequest, PublisherError


@dataclass(frozen=True)
class AwsStorageConfig:
    region: str
    table_name: str
    s3_bucket: str
    s3_prefix: str = "l4"
    inline_json_max_bytes: int = 256 * 1024
    max_transaction_bytes: int = 4 * 1024 * 1024
    max_transaction_items: int = 100
    retry_seconds: float = 1.0
    connect_timeout: float = 5.0
    read_timeout: float = 30.0

    def __post_init__(self):
        if not all(type(v) is str and v for v in (self.region, self.table_name, self.s3_bucket, self.s3_prefix)):
            raise ValueError("AWS resource identifiers must be explicit")
        if not self.s3_prefix.strip("/") or self.s3_prefix.startswith("/"):
            raise ValueError("S3 prefix must be a relative object prefix")
        for v, maximum in [(self.inline_json_max_bytes, 400 * 1024),
                           (self.max_transaction_bytes, 4 * 1024 * 1024),
                           (self.max_transaction_items, 100)]:
            if type(v) is not int or not 1 <= v <= maximum:
                raise ValueError("Invalid storage size or count bound")
        if self.max_transaction_items < 2:
            raise ValueError("A transaction needs space for a record and META")
        for v in (self.retry_seconds, self.connect_timeout, self.read_timeout):
            if type(v) not in (int, float) or not 0 < v < float("inf"):
                raise ValueError("Timeouts and retry interval must be finite and positive")


@dataclass(frozen=True)
class Upload:
    key: str
    content_type: str
    size_bytes: int
    sha256: str
    body: bytes | None = None
    file: CompletedFile | None = None


@dataclass(frozen=True)
class EncodedPublication:
    items_json: str
    meta_json: str | None
    uploads: tuple[Upload, ...]


def attribute(value):
    if value is None:
        return {"NULL": True}
    if type(value) is str:
        return {"S": value}
    if type(value) is bool:
        return {"BOOL": value}
    if type(value) is int:
        return {"N": str(value)}
    raise PublisherError("Only flat, typed header values are stored in DynamoDB")


def typed_item(item):
    return {k: attribute(v) for k, v in item.items()}


def plain_item(item):
    result = {}
    for key, value in item.items():
        if "S" in value:
            result[key] = value["S"]
        elif "N" in value:
            result[key] = int(value["N"])
        elif "BOOL" in value:
            result[key] = value["BOOL"]
        elif "NULL" in value:
            result[key] = None
        else:
            raise PublisherError("Unexpected DynamoDB header type")
    return result


def item_size_bound(item):
    """UTF-8 names/strings, one byte for bool/null, conservative integer bound.

    DynamoDB's number encoding is approximate in AWS docs. Decimal digit count
    plus two is an upper bound for our integer-only headers, not JSON wire size.
    """
    total = 0
    for key, value in item.items():
        total += len(key.encode("utf-8"))
        if type(value) is str:
            total += len(value.encode("utf-8"))
        elif value is None or type(value) is bool:
            total += 1
        elif type(value) is int:
            total += len(str(value)) + 2
        else:
            raise PublisherError("Unsupported item sizing type")
    return total


class AwsCodec:
    def __init__(self, config: AwsStorageConfig, job_id: str, start_token: str):
        self.config, self.job_id, self.start_token = config, job_id, start_token

    def key(self, sha256, extension):
        return f"{self.config.s3_prefix.rstrip('/')}/{quote(self.job_id, safe='')}/{sha256}.{extension}"

    def encode(self, publication: Publication):
        # Store order already puts works/results before their dependent records.
        # Coalesce same keys before splitting; Store never creates duplicates itself.
        records = {r.record_key: r for r in publication.records}
        files = {f.file_ref: f for f in publication.files}
        items, uploads, meta = [], {}, None
        for key, record in records.items():
            body = record.body()
            item = {"job_id": self.job_id, "record_key": key, "updated_at": record.updated_at}
            if key == "META":
                meta = item | body
                continue
            if key.startswith("FILE#"):
                descriptor = files.get(body["file_ref"])
                if descriptor is None:
                    raise PublisherError("FILE publication is missing its completed descriptor")
                extension = {"image/png": "png", "application/json": "json"}.get(descriptor.content_type, "bin")
                s3_key = self.key(descriptor.sha256, extension)
                uploads[s3_key] = Upload(s3_key, descriptor.content_type, descriptor.size_bytes,
                                         descriptor.sha256, file=descriptor)
                item.update({k: v for k, v in body.items() if k != "source_metadata"})
                item.update(source_metadata_json=dumps(body["source_metadata"]),
                            s3_bucket=self.config.s3_bucket, s3_key=s3_key)
            else:
                if not key.startswith("RESULT#"):
                    for name in ("id", "work_id", "task_id", "action_id", "status", "result_ref",
                                 "started_at", "finished_at"):
                        if name in body:
                            item[name] = body[name]
                else:
                    item["result_ref"] = key.removeprefix("RESULT#")
                raw = record.body_json.encode("utf-8")
                digest = hashlib.sha256(raw).hexdigest()
                item.update(size_bytes=len(raw), sha256=digest, body_location="inline", body_json=record.body_json)
                # Reserve a full 38-digit publish_seq when testing inline fit.
                if len(raw) > self.config.inline_json_max_bytes or item_size_bound(item | {"publish_seq": 10**38 - 1}) > 400 * 1024:
                    s3_key = self.key(digest, "json")
                    uploads[s3_key] = Upload(s3_key, "application/json", len(raw), digest, body=raw)
                    item.pop("body_json")
                    item.update(body_location="s3", s3_bucket=self.config.s3_bucket, s3_key=s3_key)
            if item_size_bound(item | {"publish_seq": 10**38 - 1}) > 400 * 1024:
                raise PublisherError("DynamoDB headers exceed the item limit")
            items.append(item)
        return EncodedPublication(dumps(items), None if meta is None else dumps(meta), tuple(uploads.values()))

    def requests(self, encoded: EncodedPublication, *, last_seq: int, saved_meta: dict):
        remaining = loads(encoded.items_json)
        target_meta = saved_meta if encoded.meta_json is None else loads(encoded.meta_json)
        if item_size_bound(target_meta | {"last_saved_seq": 10**38 - 1,
                                          "start_token": self.start_token}) > 400 * 1024:
            raise PublisherError("META exceeds its item limit")
        requests, offset = [], 0
        while offset < len(remaining) or not requests:
            seq = last_seq + len(requests) + 1
            chunk = []
            # Use the larger META representation while packing. Only the last
            # transaction in a publication applies its new META fields.
            reserve = max(item_size_bound(saved_meta), item_size_bound(target_meta)) + 256
            size = reserve
            while offset < len(remaining) and len(chunk) < self.config.max_transaction_items - 1:
                candidate = remaining[offset] | {"publish_seq": seq}
                candidate_size = item_size_bound(candidate)
                if size + candidate_size > self.config.max_transaction_bytes:
                    break
                chunk.append(candidate)
                size += candidate_size
                offset += 1
            if not chunk and offset < len(remaining):
                raise PublisherError("Record cannot fit with META in one transaction")
            meta = dict(target_meta if offset == len(remaining) else saved_meta)
            meta.update(job_id=self.job_id, record_key="META", start_token=self.start_token,
                        last_saved_seq=seq, publish_seq=seq)
            names = {"#seq": "last_saved_seq", "#owner": "start_token"}
            values = {":prev": {"N": str(seq - 1)}, ":owner": {"S": self.start_token}}
            setters = []
            for n, (key, value) in enumerate(meta.items()):
                if key in {"job_id", "record_key", "start_token"}:
                    continue
                names[f"#m{n}"] = key
                values[f":m{n}"] = attribute(value)
                setters.append(f"#m{n} = :m{n}")
            operations = [{"Put": {"TableName": self.config.table_name, "Item": typed_item(item)}} for item in chunk]
            operations.append({"Update": {"TableName": self.config.table_name,
                "Key": typed_item({"job_id": self.job_id, "record_key": "META"}),
                "ConditionExpression": "#seq = :prev AND #owner = :owner",
                "UpdateExpression": "SET " + ", ".join(setters),
                "ExpressionAttributeNames": names, "ExpressionAttributeValues": values}})
            token = uuid4().hex
            payload = {"TransactItems": operations, "ClientRequestToken": token}
            requests.append(PublishRequest(seq, token, dumps(payload), dumps(meta)))
            saved_meta = meta
        return tuple(requests)
