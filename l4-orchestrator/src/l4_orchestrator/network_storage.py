"""Completed JSON records in a caller-selected directory, registered for reading."""
import asyncio
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from uuid import uuid4

from .tools.record_reader import RecordReader, RecordSource
from .storage.models import CompletedFile


@dataclass(frozen=True)
class SavedNetworkRecord:
    record_ref: str
    sha256: str


class LocalNetworkStore:
    def __init__(self, root: Path, reader: RecordReader, *, max_record_bytes: int):
        root = Path(root)
        if not root.is_absolute():
            raise ValueError("The caller must provide an absolute network record directory")
        self.root = root.resolve(strict=True)
        if not self.root.is_dir():
            raise ValueError("The network record directory must already exist")
        if type(max_record_bytes) is not int or max_record_bytes < 1:
            raise ValueError("max_record_bytes must be a positive integer")
        self.reader, self.max_record_bytes = reader, max_record_bytes
        self._completed: dict[str, CompletedFile] = {}

    async def save(self, record: dict) -> SavedNetworkRecord:
        # Bytes are fixed before handing work to disk. Never append to a published record.
        raw = json.dumps(record, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
        if len(raw) > self.max_record_bytes:
            raise ValueError("The complete network record exceeds max_record_bytes")
        identifier = uuid4().hex
        ref = "network://records/" + identifier
        path = self.root / (identifier + ".json")
        digest = hashlib.sha256(raw).hexdigest()

        def write():
            created = False
            try:
                with path.open("xb") as handle:
                    created = True
                    handle.write(raw)
            except Exception:
                if created:
                    path.unlink(missing_ok=True)
                raise

        async def persist():
            await asyncio.to_thread(write)
            self.reader.register(ref, RecordSource(path, digest))
            self._completed[ref] = CompletedFile(ref, path, "application/json", len(raw), digest)
            return SavedNetworkRecord(ref, digest)

        # One task owns both the disk work and registration. Repeated caller cancellation
        # must not abandon an already running disk thread between those two operations.
        writing = asyncio.create_task(persist())
        interrupted = None
        while True:
            try:
                saved = await asyncio.shield(writing)
                break
            except asyncio.CancelledError as exc:
                if writing.cancelled():
                    raise
                interrupted = interrupted or exc
        if interrupted is not None:
            raise interrupted
        return saved

    def completed_files(self) -> tuple[CompletedFile, ...]:
        """Includes background capture files completed during capture.close()."""
        return tuple(self._completed.values())
