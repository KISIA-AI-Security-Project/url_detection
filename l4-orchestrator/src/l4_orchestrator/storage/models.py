"""Immutable recording and publication values; no SDK or AWS dependency."""
from dataclasses import dataclass
from pathlib import Path
import re

from ..json_values import dumps, loads
from ..execution_control import StoreError


def text_id(value, name, max_bytes=None):
    if type(value) is not str or not value or "\0" in value:
        raise StoreError(f"{name} must be a nonempty string without NUL")
    if max_bytes is not None and len(value.encode("utf-8")) > max_bytes:
        raise StoreError(f"{name} exceeds its UTF-8 key limit")
    return value


@dataclass(frozen=True)
class CompletedFile:
    """Trusted producer input, never a model argument or a guessed ref path."""
    file_ref: str
    local_path: Path
    content_type: str
    size_bytes: int
    sha256: str
    source_metadata_json: str = "{}"

    def __post_init__(self):
        text_id(self.file_ref, "file_ref", 1019)
        text_id(self.content_type, "content_type")
        path = Path(self.local_path)
        if not path.is_absolute():
            raise StoreError("Completed file path must be absolute")
        if type(self.size_bytes) is not int or self.size_bytes < 0:
            raise StoreError("File size must be a nonnegative integer")
        if type(self.sha256) is not str or not re.fullmatch("[a-f0-9]{64}", self.sha256):
            raise StoreError("File SHA-256 must be lowercase hexadecimal")
        metadata = loads(self.source_metadata_json)
        if type(metadata) is not dict:
            raise StoreError("Source metadata must be a JSON object")
        object.__setattr__(self, "local_path", path)
        object.__setattr__(self, "source_metadata_json", dumps(metadata))

    def public_metadata(self):
        return dict(file_ref=self.file_ref, content_type=self.content_type,
                    size_bytes=self.size_bytes, sha256=self.sha256,
                    source_metadata=loads(self.source_metadata_json))


@dataclass(frozen=True)
class Record:
    record_key: str
    body_json: str
    updated_at: str

    @classmethod
    def make(cls, key, body, now):
        text_id(key, "record_key", 1024)
        return cls(key, dumps(body), now)

    def body(self):
        return loads(self.body_json)


@dataclass(frozen=True)
class Publication:
    number: int
    records: tuple[Record, ...]
    files: tuple[CompletedFile, ...] = ()
    terminal: bool = False


@dataclass(frozen=True)
class PublishRequest:
    seq: int
    token: str
    request_json: str
    meta_json: str

    def request(self):
        return loads(self.request_json)


class PublisherError(StoreError):
    pass


class DuplicateJobError(PublisherError):
    pass


class RetryableWriteError(PublisherError):
    pass


class ConditionalWriteError(PublisherError):
    pass
