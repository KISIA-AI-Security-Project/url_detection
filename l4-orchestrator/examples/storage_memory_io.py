"""Deterministic AWS protocol stand-in for the storage example/tests, not persistence."""
import hashlib
from copy import deepcopy

from l4_orchestrator.storage.aws_codec import plain_item
from l4_orchestrator.storage.models import ConditionalWriteError, RetryableWriteError, PublisherError


class MemoryStorageIO:
    def __init__(self, *, page_size=2):
        self.items, self.objects, self.tokens = {}, {}, {}
        self.requests, self.uploads, self.history = [], [], []
        self.page_size = page_size
        self.lose_initial_reply = False
        self.lose_reply_at = set()
        self.reject_once_at = set()
        self.expire_tokens_on_loss = False
        self.permanent_error_at = set()

    async def put_initial_meta(self, meta):
        key = (meta["job_id"], "META")
        if key in self.items:
            raise ConditionalWriteError("META already exists")
        self.items[key] = deepcopy(meta)
        if self.lose_initial_reply:
            self.lose_initial_reply = False
            raise RetryableWriteError("Initial reply lost after commit")

    async def get_meta(self, job_id):
        return await self.get_item(job_id, "META")

    async def get_item(self, job_id, record_key):
        return deepcopy(self.items.get((job_id, record_key)))

    async def query(self, job_id, prefix, cursor=None):
        rows = sorted((k, v) for (j, k), v in self.items.items() if j == job_id and k.startswith(prefix))
        rows = [(k, v) for k, v in rows if cursor is None or k > cursor]
        chosen = rows[:self.page_size]
        nxt = chosen[-1][0] if len(rows) > self.page_size else None
        return deepcopy([v for _, v in chosen]), nxt

    async def upload(self, upload):
        raw = upload.body if upload.body is not None else upload.file.local_path.read_bytes()
        if len(raw) != upload.size_bytes or hashlib.sha256(raw).hexdigest() != upload.sha256:
            raise PublisherError("File changed")
        self.objects[upload.key] = raw
        self.uploads.append(upload.key)

    async def download(self, bucket, key):
        return self.objects[key]

    async def transact(self, request):
        payload = request.request()
        self.requests.append(payload)
        if request.seq in self.permanent_error_at:
            raise PublisherError("AccessDenied")
        if request.seq in self.reject_once_at:
            self.reject_once_at.remove(request.seq)
            raise RetryableWriteError("Throttled before commit")
        if request.token in self.tokens:
            assert self.tokens[request.token] == request.request_json
            return
        ops = payload["TransactItems"]
        assert len(ops) <= 100
        keys = []
        next_items = deepcopy(self.items)
        for operation in ops:
            if "Put" in operation:
                row = plain_item(operation["Put"]["Item"])
                key = (row["job_id"], row["record_key"])
                next_items[key] = row
            else:
                update = operation["Update"]
                key_row = plain_item(update["Key"])
                key = (key_row["job_id"], key_row["record_key"])
                row = next_items[key]
                names, values = update["ExpressionAttributeNames"], plain_item(update["ExpressionAttributeValues"])
                if row["last_saved_seq"] != values[":prev"] or row["start_token"] != values[":owner"]:
                    raise ConditionalWriteError("Sequence/owner condition failed")
                for setter in update["UpdateExpression"].removeprefix("SET ").split(", "):
                    attr, val = setter.split(" = ")
                    row[names[attr]] = values[val]
            keys.append(key)
        assert len(keys) == len(set(keys))
        # Inspect the committed public state, including transaction split edges.
        for (job, key), row in next_items.items():
            if key.startswith("TASK#"):
                assert (job, "WORK#" + row["work_id"]) in next_items
            if key.startswith(("TASK#", "ACTION#")) and row.get("result_ref"):
                assert (job, "RESULT#" + row["result_ref"]) in next_items
            if row.get("body_location") == "s3" or key.startswith("FILE#"):
                assert row["s3_key"] in self.objects
        self.items = next_items
        self.tokens[request.token] = request.request_json
        self.history.append(deepcopy(next_items))
        if request.seq in self.lose_reply_at:
            self.lose_reply_at.remove(request.seq)
            if self.expire_tokens_on_loss:
                self.tokens.clear()
            raise RetryableWriteError("Reply lost after commit")
