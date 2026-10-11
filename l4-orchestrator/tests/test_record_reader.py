from sdk_tool_checks import run_native_steps
import asyncio
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from l4_orchestrator.ports import Authorization
from l4_orchestrator.tools.record_reader import RecordReader, RecordSource


ROOT = Path(__file__).resolve().parents[2]
REF = "records/a5091407d4c2c2f5b8cb95a3acc6ee59/1/l3/l3.json"
SOURCE = ROOT / "docs/l4-first-investigation-20260928/sources/s3" / REF
SHA256 = "115d3c0033d1f6f51fcaa403412b394dd884279c6b51606d1ff21a92dbbdcfd6"
DOCUMENT = "/observation/raw/html/document"
HTML = "/observation/raw/html/source"


def reader():
    return RecordReader({REF: RecordSource(SOURCE, SHA256)}, max_data_bytes=4096)


def read(pointer, ref=REF):
    return reader().read({"record_ref": ref, "pointer": pointer})


def test_real_record_selected_document_then_original_html():
    original_bytes = SOURCE.read_bytes()
    stored = json.loads(original_bytes)
    document = read(DOCUMENT)
    assert document["status"] == "ok" and document["error"] is None
    assert document["data"] == stored["observation"]["raw"]["html"]["document"]
    assert document["data"]["title"] == "SFE"
    assert document["data"]["visible_text"] == "Loading..."
    assert "runtime visibility unobserved" in document["data"]["text_scope"]
    assert "source" not in document["data"] and "signals" not in document["data"]
    detail = read(HTML, document["record_ref"])
    assert detail["status"] == "ok"
    assert detail["data"] == stored["observation"]["raw"]["html"]["source"]
    assert hashlib.sha256(detail["data"].encode()).hexdigest() == document["data"]["sha256"]
    assert detail["source_sha256"] == document["source_sha256"] == SHA256
    assert SOURCE.read_bytes() == original_bytes


def test_no_silent_truncation_missing_value_or_unregistered_path():
    assert read("")["error"]["code"] == "VALUE_TOO_LARGE"
    assert read("/observation/missing")["error"]["code"] == "VALUE_NOT_FOUND"
    empty = read("/observation/raw/html/inputs")
    assert empty["status"] == "ok" and empty["data"] == []
    for ref in ["../secrets.json", "C:/secret.json", "records/another-job/1/l3/l3.json"]:
        result = read(DOCUMENT, ref)
        assert result["error"]["code"] == "RECORD_NOT_REGISTERED" and result["data"] is None
    with pytest.raises(ValidationError):
        reader().read({"record_ref": REF, "pointer": DOCUMENT, "path": "C:/secret.json"})


def test_changed_or_unavailable_source_is_not_a_new_observation(tmp_path):
    path = tmp_path / "record.json"
    path.write_text('{"x":1}', encoding="utf-8")
    source = RecordSource(path, hashlib.sha256(path.read_bytes()).hexdigest())
    tool = RecordReader({"r": source}, max_data_bytes=100)
    path.write_text('{"x":2}', encoding="utf-8")
    assert tool.read({"record_ref": "r", "pointer": "/x"})["error"]["code"] == "RECORD_CHANGED"
    path.unlink()
    assert tool.read({"record_ref": "r", "pointer": "/x"})["error"]["code"] == "RECORD_UNAVAILABLE"


def test_pointer_values_and_invalid_json(tmp_path):
    path = tmp_path / "record.json"
    path.write_text('{"a/b":{"~key":[null,false,0,"",0.1]}}', encoding="utf-8")
    tool = RecordReader({"r": RecordSource(path, hashlib.sha256(path.read_bytes()).hexdigest())}, max_data_bytes=100)
    for index, value in enumerate([None, False, 0, "", 0.1]):
        result = tool.read({"record_ref": "r", "pointer": f"/a~1b/~0key/{index}"})
        assert result["status"] == "ok" and result["data"] == value
        assert type(result["data"]) is type(value)
    for pointer in ["a/b", "/bad~", "/bad~2"]:
        assert tool.read({"record_ref": "r", "pointer": pointer})["error"]["code"] == "INVALID_POINTER"
    for pointer in ["/a~1b/~0key/01", "/a~1b/~0key/-1", "/a~1b/~0key/9"]:
        assert tool.read({"record_ref": "r", "pointer": pointer})["error"]["code"] == "VALUE_NOT_FOUND"
    for content in ['{"x":NaN}', '{"x":1e999}', '{"x":1e-400}', '{"x":1.0000000000000001}',
                    '{"x":1,"x":2}', r'{"x":"\ud800"}']:
        path.write_text(content, encoding="utf-8")
        bad = RecordReader({"r": RecordSource(path, hashlib.sha256(path.read_bytes()).hexdigest())}, max_data_bytes=100)
        assert bad.read({"record_ref": "r", "pointer": "/x"})["error"]["code"] == "INVALID_RECORD"


def test_real_selected_lookup_through_sdk_store_and_following_manager_input():
    original = SOURCE.read_bytes()
    proof = asyncio.run(run_native_steps({"record_reader": reader()}, [
        ("record_reader", {"record_ref": REF, "pointer": DOCUMENT}),
        ("record_reader", {"record_ref": REF, "pointer": HTML})], initial_findings={"record_ref": REF}))
    assert len(proof.manager_inputs) == 3
    assert proof.results == [read(DOCUMENT), read(HTML)]
    assert "<!DOCTYPE" not in json.dumps(proof.manager_inputs[1])
    assert "evidence_record" not in json.dumps(proof.manager_inputs)
    assert SOURCE.read_bytes() == original
    # Each new result is delivered once; earlier turns remain in SDK history.
    assert all(len(value["new_results"]) == 1 for value in proof.manager_inputs[1:])
