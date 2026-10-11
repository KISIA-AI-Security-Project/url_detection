"""Read a requested JSON value from a registered, unchanged local record."""
import asyncio
from dataclasses import dataclass
from decimal import Decimal
import hashlib
import json
import math
from pathlib import Path
import re
from typing import Mapping

from pydantic import Field

from ..ports import ExecutionPort
from ..schemas import WireModel


class ReadRecordInput(WireModel):
    record_ref: str = Field(min_length=1)
    pointer: str  # JSON Pointer; an empty string selects the whole document.


@dataclass(frozen=True)
class RecordSource:
    path: Path
    sha256: str


def _select(document, pointer):
    if pointer == "":
        return document
    if not pointer.startswith("/") or re.search(r"~(?![01])", pointer):
        raise ValueError("Invalid JSON Pointer")
    value = document
    for token in pointer[1:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict):
            value = value[token]
        elif isinstance(value, list) and re.fullmatch(r"0|[1-9][0-9]*", token):
            value = value[int(token)]
        else:
            raise KeyError(token)
    return value


def _invalid_constant(value):
    raise ValueError("Non-JSON number")


def _finite_float(value):
    number = float(value)
    if not math.isfinite(number) or Decimal(str(number)) != Decimal(value):
        raise ValueError("Number cannot be represented without changing its decimal value")
    return number


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


class RecordReader:
    """The caller supplies permitted files and a data-size limit, not the model."""

    def __init__(self, sources: Mapping[str, RecordSource], *, max_data_bytes: int):
        if type(max_data_bytes) is not int or max_data_bytes < 1:
            raise ValueError("max_data_bytes must be positive")
        self._sources = {}
        self._max_data_bytes = max_data_bytes
        for ref, source in sources.items():
            self.register(ref, source)

    def register(self, record_ref: str, source: RecordSource):
        """Trusted callers can add a completed file; no Tool input exposes this.

        A reference cannot be redirected to a different file or hash.
        """
        if not record_ref or not isinstance(source, RecordSource) or not re.fullmatch(r"[0-9a-f]{64}", source.sha256):
            raise ValueError("Each source needs a reference and lowercase SHA-256")
        existing = self._sources.get(record_ref)
        if existing is not None and existing != source:
            raise ValueError("A registered reference cannot be replaced")
        self._sources[record_ref] = source

    def read(self, arguments):
        request = ReadRecordInput.model_validate(arguments)
        result = {"record_ref": request.record_ref, "pointer": request.pointer,
                  "status": "error", "source_sha256": None, "data": None,
                  "error": None}

        def fail(code, message):
            result["error"] = {"code": code, "message": message}
            return result

        source = self._sources.get(request.record_ref)
        if source is None:
            return fail("RECORD_NOT_REGISTERED", "No record is registered for this reference.")
        try:
            raw = source.path.read_bytes()
        except OSError:
            return fail("RECORD_UNAVAILABLE", "The registered record could not be read.")
        if hashlib.sha256(raw).hexdigest() != source.sha256:
            return fail("RECORD_CHANGED", "The record no longer matches its registered content.")
        result["source_sha256"] = source.sha256
        try:
            document = json.loads(raw, parse_constant=_invalid_constant,
                                  parse_float=_finite_float, object_pairs_hook=_unique_object)
        except (ValueError, UnicodeError):
            return fail("INVALID_RECORD", "The stored record is not valid JSON.")
        try:
            data = _select(document, request.pointer)
        except ValueError:
            return fail("INVALID_POINTER", "Use an empty string or a valid JSON Pointer.")
        except (KeyError, IndexError):
            return fail("VALUE_NOT_FOUND", "The requested value is absent; it was not an empty result.")
        try:
            encoded = json.dumps(data, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
        except (ValueError, UnicodeError):
            return fail("INVALID_RECORD", "The requested value cannot be represented as UTF-8 JSON.")
        if len(encoded) > self._max_data_bytes:
            return fail("VALUE_TOO_LARGE", "Request a smaller JSON value; no content was truncated.")
        result.update(status="ok", data=data)
        return result

    def as_port(self):
        def prepare(request, assigned_task):
            return ReadRecordInput.model_validate(request["arguments"]).model_dump(mode="json")

        async def invoke(arguments):
            return await asyncio.to_thread(self.read, arguments)

        return ExecutionPort(
            description="Read one JSON value from an explicitly registered saved record. Returns source reference and hash; performs no new observation or interpretation.",
            kind="tool", provenance="existing_material",
            permission_description="Reads caller-registered local records only. No model-supplied file path or network access.",
            prepare=prepare, invoke=invoke,
        )
