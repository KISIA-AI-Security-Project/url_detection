"""Reference reader for the separate backend; no memory Store dependency."""
import hashlib

from ..json_values import loads
from .models import PublisherError


class AwsRecordReader:
    def __init__(self, io):
        self.io = io

    async def item(self, job_id, record_key):
        return await self.io.get_item(job_id, record_key)

    async def list_items(self, job_id, prefix):
        rows, cursor = [], None
        seen = set()
        while True:
            page, next_cursor = await self.io.query(job_id, prefix, cursor)
            rows.extend(page)
            if not next_cursor:
                return rows
            marker = repr(next_cursor)
            if marker in seen:
                raise PublisherError("DynamoDB query cursor did not advance")
            seen.add(marker)
            cursor = next_cursor

    async def body(self, item):
        location = item.get("body_location")
        if location == "inline":
            raw = item["body_json"].encode("utf-8")
        elif location == "s3":
            raw = await self.io.download(item["s3_bucket"], item["s3_key"])
        else:
            raise PublisherError("This item is not a JSON body record")
        self._verify(item, raw)
        return loads(raw.decode("utf-8"))

    async def file_bytes(self, item):
        if not item["record_key"].startswith("FILE#"):
            raise PublisherError("A FILE item is required")
        raw = await self.io.download(item["s3_bucket"], item["s3_key"])
        self._verify(item, raw)
        return raw

    @staticmethod
    def _verify(item, raw):
        if len(raw) != item["size_bytes"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise PublisherError("Downloaded body differs from its published size or SHA-256")
