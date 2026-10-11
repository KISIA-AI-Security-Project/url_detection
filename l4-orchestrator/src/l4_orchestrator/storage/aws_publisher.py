"""One publisher: sequential confirmed writes, retained immutable inflight state."""
import asyncio

from ..json_values import loads
from .aws_codec import AwsCodec
from .models import (ConditionalWriteError, DuplicateJobError, PublisherError,
                     RetryableWriteError)


class AwsPublisher:
    def __init__(self, store, io, config):
        self.store, self.io, self.config = store, io, config
        self.codec = AwsCodec(config, store.job_id, store.start_token)
        self._initialized = False
        self._running = False
        self._saved_meta = store.initial_meta.body() | {
            "job_id": store.job_id, "record_key": "META", "start_token": store.start_token,
            "last_saved_seq": 0, "publish_seq": 0}
        self._encoded = None
        self._upload_index = 0
        self._requests = ()
        self._request_index = 0

    @property
    def inflight_requests(self):
        return self._requests

    async def _meta(self):
        while True:
            try:
                return await self.io.get_meta(self.store.job_id)
            except RetryableWriteError:
                await asyncio.sleep(self.config.retry_seconds)

    async def initialize(self):
        if self._initialized:
            return
        if self.store._publisher_owner is None:
            self.store._attach_publisher(self)
        elif self.store._publisher_owner is not self:
            raise PublisherError("Another publisher owns this Store")
        while True:
            try:
                await self.io.put_initial_meta(self._saved_meta)
                break
            except (ConditionalWriteError, RetryableWriteError) as exc:
                saved = await self._meta()
                if saved is not None:
                    if saved.get("start_token") != self.store.start_token:
                        raise DuplicateJobError("L4 already started for this job_id") from exc
                    if saved != self._saved_meta:
                        raise PublisherError("Initial META differs from this fixed start request") from exc
                    break
                if isinstance(exc, ConditionalWriteError):
                    raise PublisherError("Initial write condition failed without a readable META") from exc
                await asyncio.sleep(self.config.retry_seconds)
        self._initialized = True

    async def run(self):
        if self.store._publisher_owner is not None and self.store._publisher_owner is not self:
            raise PublisherError("Another publisher owns this Store")
        if self._running or self.store._publisher_done:
            raise PublisherError("Publisher is already running or finished")
        self._running = True
        try:
            await self.initialize()
            while True:
                self.store._changed.clear()
                publication = self.store._claim()
                if publication is None:
                    if self.store.records_sealed:
                        self.store._publisher_done = True
                        self.store._changed.set()
                        return
                    await self.store._changed.wait()
                    continue
                if self._encoded is None:
                    self._encoded = self.codec.encode(publication)
                while self._upload_index < len(self._encoded.uploads):
                    upload = self._encoded.uploads[self._upload_index]
                    try:
                        await self.io.upload(upload)
                    except RetryableWriteError:
                        await asyncio.sleep(self.config.retry_seconds)
                        continue
                    self._upload_index += 1
                if not self._requests:
                    self._requests = self.codec.requests(self._encoded,
                        last_seq=self._saved_meta["last_saved_seq"], saved_meta=self._saved_meta)
                while self._request_index < len(self._requests):
                    request = self._requests[self._request_index]
                    try:
                        await self.io.transact(request)
                    except (ConditionalWriteError, RetryableWriteError) as exc:
                        saved = await self._meta()
                        if saved is None or saved.get("start_token") != self.store.start_token:
                            raise PublisherError("Cannot confirm write ownership") from exc
                        seq = saved.get("last_saved_seq")
                        if type(seq) is not int:
                            raise PublisherError("Invalid saved sequence") from exc
                        if seq < request.seq:
                            if seq != request.seq - 1 or isinstance(exc, ConditionalWriteError):
                                raise PublisherError("Saved sequence does not match the inflight request") from exc
                            await asyncio.sleep(self.config.retry_seconds)
                            continue
                    self._saved_meta = loads(request.meta_json)
                    self._request_index += 1
                self.store._ack(publication, self._saved_meta["last_saved_seq"])
                self._encoded = None
                self._upload_index = self._request_index = 0
                self._requests = ()
        except BaseException as exc:
            error = PublisherError("Publisher was cancelled; unconfirmed data retained") if isinstance(exc, asyncio.CancelledError) else exc
            self.store._publisher_failed(error)
            raise
        finally:
            self._running = False
