"""Completed HTML files in the caller's Bash work directory."""
import asyncio
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from uuid import uuid4

from .storage.models import CompletedFile


HTML_CONTENT_TYPE = "text/html; charset=utf-8"


@dataclass(frozen=True)
class SavedPageExport:
    file_ref: str
    relative_path: str
    size_bytes: int
    sha256: str


class LocalPageExportStore:
    """The caller must use this root as BashEnvironment.cwd as well."""

    def __init__(self, root: Path):
        root = Path(root)
        if not root.is_absolute():
            raise ValueError("The caller must supply an absolute export directory")
        self.root = root.resolve(strict=True)
        if not self.root.is_dir():
            raise ValueError("The export directory must already exist")
        self._completed: dict[str, CompletedFile] = {}

    @staticmethod
    def _write(path, raw):
        created = False
        try:
            with path.open("xb") as handle:
                created = True
                if handle.write(raw) != len(raw):
                    raise OSError("The complete HTML was not written")
        except Exception:
            if created:
                path.unlink(missing_ok=True)
            raise

    async def save_html(self, raw: bytes, metadata: dict) -> SavedPageExport:
        if type(raw) is not bytes:
            raise TypeError("Expected UTF-8 HTML bytes")
        raw.decode("utf-8")  # No replacement, newline conversion or source rewriting.
        metadata_json = json.dumps(metadata, ensure_ascii=False, allow_nan=False)
        identifier = uuid4().hex
        name = identifier + ".html"
        ref = "artifact://page-exports/" + identifier
        digest = hashlib.sha256(raw).hexdigest()
        completed = CompletedFile(
            file_ref=ref, local_path=self.root / name, content_type=HTML_CONTENT_TYPE,
            size_bytes=len(raw), sha256=digest, source_metadata_json=metadata_json,
        )

        async def persist():
            await asyncio.to_thread(self._write, completed.local_path, raw)
            # Publish the descriptor only after close/flush succeeds.
            self._completed[ref] = completed
            return SavedPageExport(ref, name, len(raw), digest)

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
            except Exception as exc:
                if interrupted is not None:
                    raise interrupted from exc
                raise
        # A cancelled caller receives no success. Any completed file remains
        # discoverable by the trusted execution environment through completed_files().
        if interrupted is not None:
            raise interrupted
        return saved

    def completed_file(self, file_ref: str) -> CompletedFile:
        """Internal descriptor lookup, not an Agent Tool or AWS publication."""
        return self._completed[file_ref]

    def completed_files(self) -> tuple[CompletedFile, ...]:
        """Includes completed writes whose callers were subsequently cancelled."""
        return tuple(self._completed.values())
