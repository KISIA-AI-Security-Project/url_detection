"""PNG files under a caller-selected directory; no AWS or retention policy."""
import asyncio
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from uuid import uuid4

from .storage.models import CompletedFile


@dataclass(frozen=True)
class SavedScreenshot:
    artifact_ref: str
    sha256: str


class LocalScreenshotStore:
    """Keep this instance for the run. Only its successfully saved refs can be read."""

    def __init__(self, root: Path):
        root = Path(root)
        if not root.is_absolute():
            raise ValueError("The caller must supply an absolute screenshot directory")
        self.root = root.resolve(strict=True)
        if not self.root.is_dir():
            raise ValueError("The screenshot directory must already exist")
        self._saved: dict[str, tuple[Path, str]] = {}
        self._completed: dict[str, CompletedFile] = {}

    async def save_png(self, png: bytes, metadata: dict) -> SavedScreenshot:
        return await asyncio.to_thread(self._save, png, metadata)

    def _save(self, png, metadata):
        if type(png) is not bytes or not png.startswith(b"\x89PNG\r\n\x1a\n"):
            raise ValueError("Expected PNG bytes from the capture operation")
        digest = hashlib.sha256(png).hexdigest()
        identifier = uuid4().hex
        ref = "artifact://screenshots/" + identifier
        record = json.dumps({"artifact_ref": ref, "sha256": digest,
                             "media_type": "image/png", "byte_length": len(png),
                             "capture": metadata}, ensure_ascii=False, allow_nan=False)
        folder = self.root / identifier
        # Exclusive creation: neither a repeated ID nor a symlink can overwrite an artifact.
        folder.mkdir()
        created = []
        try:
            image_path = folder / "image.png"
            with image_path.open("xb") as handle:
                created.append(image_path)
                handle.write(png)
            metadata_path = folder / "capture.json"
            with metadata_path.open("x", encoding="utf-8") as handle:
                created.append(metadata_path)
                handle.write(record)
        except Exception:
            # Only the files created by this attempt; never remove an existing directory tree.
            for path in reversed(created):
                path.unlink(missing_ok=True)
            folder.rmdir()
            raise
        self._saved[ref] = (image_path, digest)
        self._completed[ref] = CompletedFile(ref, image_path, "image/png", len(png), digest,
                                             json.dumps(metadata, ensure_ascii=False, allow_nan=False))
        return SavedScreenshot(ref, digest)

    def completed_files(self) -> tuple[CompletedFile, ...]:
        """Trusted descriptors after save_png; Store registration is the caller's job."""
        return tuple(self._completed.values())

    async def load_png(self, artifact_ref: str, sha256: str) -> bytes:
        """Used internally at model transmission, not exposed as another Agent Tool."""
        return await asyncio.to_thread(self._load, artifact_ref, sha256)

    def _load(self, artifact_ref, sha256):
        source = self._saved.get(artifact_ref)
        if source is None:
            raise ValueError("The screenshot reference is not registered for this run")
        path, expected = source
        if sha256 != expected:
            raise ValueError("The screenshot reference and digest do not match")
        if path.resolve(strict=True) != path:
            raise ValueError("The screenshot location has changed")
        png = path.read_bytes()
        if hashlib.sha256(png).hexdigest() != expected:
            raise ValueError("The saved screenshot has changed")
        return png
