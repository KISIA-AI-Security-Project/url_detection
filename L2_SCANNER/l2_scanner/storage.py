"""L2 Analysis Record 파일 저장 

[목적]
scan()이 만든 Raw Data(dict)를 검증 가능한 JSON 파일로 저장한다.

[입력]  scan() 반환 dict (Raw Evidence(raw)와 Analysis Record(signals)를 포함)
[출력]  저장된 파일의 절대 경로 (pathlib.Path)

[설계 근거]
- 분석과 데이터화의 분리: scan()은 저장을 모른다. 저장은 호출자(main.py, 향후 Fargate Job)가 이 모듈을 통해 수행한다. 분석 항목이 바뀌어도 저장이 안 흔들리게.
- 저장 실패 != 완료: 임시 파일에 전부 쓴 뒤 os.replace로 원자적 교체한다. 쓰다 만 파일이 완료된 Record처럼 보이는 상태를 만들지 않는다. 실패는 예외로 전파.
- 원본 보존: 같은 이름의 파일이 이미 있으면 덮어쓰지 않고 순번을 붙여 새 파일로 저장한다. 원본 Evidence는 수정하지 않고 새 버전으로 보존.
- job_id/attempt_id는 넣지 않는다: 시스템 공통 식별자는 오케스트레이터가 부여 (Evidence 스키마 팀 확정 대기). 파일명은 스캔 시각 + URL 해시로만 구성해, AWS팀이 어떤 경로 규격으로도 옮겨 담을 수 있게 한다.
"""
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from l2_scanner.config.tuning import RECORD_OUTPUT_DIR


def _timestamp_utc(result: dict) -> str:
    """결과의 스캔 완료 시각을 UTC 컴팩트 표기(20260831T072010Z)로 만든다.

    finished_at이 없거나 못 읽으면 현재 시각(UTC)으로 대신한다.
    파일명은 색인용일 뿐, 정본 시각은 결과 JSON 안의 scan 트리에 있다.
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
    # 원본 URL의 sha256 앞 10자. 같은 시각에 여러 URL을 스캔해도 파일명이 겹치지 않게.
    url = (result.get("target") or {}).get("original_url") or ""
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:10]


def default_filename(result: dict) -> str:
    # 결과 dict에서 기본 파일명을 만든다: l2_{완료시각 UTC}_{URL 해시}.json
    return f"l2_{_timestamp_utc(result)}_{_url_digest(result)}.json"


def save_record(result: dict, output_dir: str | Path = RECORD_OUTPUT_DIR,
                filename: str | None = None) -> Path:
    """L2 결과 dict를 JSON 파일로 저장하고 저장된 경로를 반환한다.

    입력: result     - scan() 반환 dict
         output_dir - 저장 디렉터리 (없으면 생성. 기본값은 config.tuning.RECORD_OUTPUT_DIR)
         filename   - 파일명 지정 (생략 시 default_filename 규칙)
    출력: 저장된 파일의 절대 경로

    저장 실패(권한, 디스크 등)는 삼키지 않고 예외로 전파한다. (저장이 안 된 Record를 완료로 취급하는 것이 최악의 상태이기 때문.)
    """
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    name = filename or default_filename(result)
    path = out_dir / name

    # 이미 있으면 덮어쓰지 않고 순번을 붙인다 (원본 보존)
    counter = 1
    while path.exists():
        path = out_dir / f"{Path(name).stem}-{counter}{Path(name).suffix}"
        counter += 1

    # 임시 파일에 전부 쓴 뒤 제자리에 놓는다. 부분 파일이 남지 않게
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        os.replace(tmp_path, path)
    finally:
        tmp_path.unlink(missing_ok=True)   # 교체 성공 시엔 이미 없고, 실패 시 잔재 제거

    return path.resolve()
