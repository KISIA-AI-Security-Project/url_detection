"""L2 Raw Evidence, Analysis Record 파일 저장

scan() 결과 dict 하나를 Raw Evidence와 Analysis Record로 분리해 파일로 저장
S3판 저장은 storage_s3.py에 있음
경로와 쓰는 순서는 이 파일의 files_to_write를 그대로 가져다 씀

[입력]  scan() 반환 dict + job_id/attempt_id (오케스트레이터가 부여. 로컬 실행은 폴백 생성)
[출력]  저장된 파일들의 절대 경로 목록 (쓴 순서 - Raw 먼저, Record 마지막)

[분리 규격] S3에서 Raw와 Record를 별도 파일, 경로로 관리
raw/{job_id}/{attempt_id}/l2/http.json   HTTP Collector 원본 (redirect_chain, headers, body)
raw/{job_id}/{attempt_id}/l2/tls.json    Certificate Collector 원본
raw/{job_id}/{attempt_id}/l2/ct.json     CT Collector 원본
records/{job_id}/{attempt_id}/l2.json    Analysis Record (target, scan, signals, errors)


"""
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from l2_scanner.config.tuning import EVIDENCE_OUTPUT_DIR

__all__ = [
    "build_record",
    "split_raw",
    "files_to_write",
    "save_evidence",
    "local_ids",
    "record_key",
    "raw_key",
    "RECORD_FILE_NAME",
    "RAW_NAMES",
]

RECORD_FILE_NAME = "l2.json"

# Raw Evidence 파일 구성 - Collector당 파일 하나, 이름 고정 (scan() 반환의 raw 트리 키와 동일)
RAW_NAMES = ("http", "tls", "ct")


def build_record(result: dict) -> dict:
    # scan() 결과에서 Analysis Record를 생성 - raw 트리만 뺀 나머지 전부.
    return {key: value for key, value in result.items() if key != "raw"}


def split_raw(result: dict) -> dict[str, dict]:
    # scan() 결과에서 Raw Evidence를 Collector별로 나눈다 - {"http": ..., "tls": ..., "ct": ...}
    # RAW_NAMES에 있는 키가 결과에 없으면 KeyError 
    raw = result["raw"]
    return {name: raw[name] for name in RAW_NAMES}


def record_key(job_id: str, attempt_id: str) -> str:
    return f"records/{job_id}/{attempt_id}/{RECORD_FILE_NAME}"


def raw_key(job_id: str, attempt_id: str, name: str) -> str:
    return f"raw/{job_id}/{attempt_id}/l2/{name}.json"


def files_to_write(result: dict, job_id: str, attempt_id: str) -> list[tuple[str, bytes]]:
    # 쓸 파일을 쓸 순서대로 (경로, 바이트)로 - Raw 파일들 먼저, Record가 마지막.

    files = [(raw_key(job_id, attempt_id, name), _json_bytes(body))
             for name, body in split_raw(result).items()]
    files.append((record_key(job_id, attempt_id), _json_bytes(build_record(result))))
    return files


def save_evidence(result: dict, job_id: str | None = None, attempt_id: str | None = None,
                  root: str | Path = EVIDENCE_OUTPUT_DIR) -> list[Path]:
    """scan() 결과를 Raw Evidence, Analysis Record 파일로 분리 저장

    입력: result     - scan() 반환 dict
         job_id     - 오케스트레이터가 부여한 식별자 (생략 시 local_ids 폴백)
         attempt_id - 오케스트레이터가 부여한 식별자 (생략 시 local_ids 폴백)
         root       - 저장 루트 (없으면 생성. 기본값은 config.tuning.EVIDENCE_OUTPUT_DIR)
    출력: 저장된 파일들의 절대 경로 (쓴 순서 - Record가 마지막)

    이미 있는 파일은 FileExistsError로 거부
    """
    if job_id is None or attempt_id is None:
        fallback_job, fallback_attempt = local_ids(result)
        job_id = job_id or fallback_job
        attempt_id = attempt_id or fallback_attempt

    saved: list[Path] = []
    for key, body in files_to_write(result, job_id, attempt_id):
        path = Path(root) / key
        path.parent.mkdir(parents=True, exist_ok=True)
        _write_atomic_no_overwrite(path, body)
        saved.append(path.resolve())
    return saved


def local_ids(result: dict) -> tuple[str, str]:
    # 오케스트레이터 없이(로컬 데모, 테스트) 돌릴 때의 경로용 폴백 식별자.
    # job_id = local-{URL 해시}, attempt_id = 스캔 완료 시각(UTC 컴팩트).
    return f"local-{_url_digest(result)}", _timestamp_utc(result)


def _timestamp_utc(result: dict) -> str:
    """결과의 스캔 완료 시각을 UTC 컴팩트 표기(20260831T072010Z)로 

    finished_at이 없거나 못 읽으면 현재 시각(UTC)으로 대신한다.
    정본 시각은 Record JSON 안의 scan 트리에 있음
    """
    finished_at = (result.get("scan") or {}).get("finished_at")
    try:
        dt = datetime.fromisoformat(finished_at)
    except (TypeError, ValueError):
        dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _url_digest(result: dict) -> str:
    # 원본 URL의 sha256 앞 10자. 같은 시각에 여러 URL을 스캔해도 경로가 겹치지 않게.
    url = (result.get("target") or {}).get("original_url") or ""
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:10]


def _json_bytes(value: dict) -> bytes:
    # ensure_ascii=False - 사람이 읽는 Evidence이므로 한글이 \uXXXX로 깨지면 안 된다
    return json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8")


def _write_atomic_no_overwrite(path: Path, body: bytes) -> None:
    # 임시 파일에 전부 쓴 뒤 제자리에 놓는다. 이미 있는 파일은 거부.
    if path.exists():
        raise FileExistsError(f"이미 저장된 Evidence 파일: {path}")
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    try:
        with open(tmp_path, "wb") as f:
            f.write(body)
        os.replace(tmp_path, path)
    finally:
        tmp_path.unlink(missing_ok=True)   # 교체 성공 시엔 이미 없고, 실패 시 잔재 제거
