"""storage 테스트 - Raw Evidence, Analysis Record 분리 저장. 

검증 대상 :
- 분리 규격: Record에는 raw가 없고, Raw는 Collector별 파일 3종(http/tls/ct)로 나뉜다
- 경로 규격: raw/{job}/{attempt}/l2/{이름}, json , records/{job}/{attempt}/l2.json
- 쓰는 순서: Raw 먼저, Record 마지막 
- Record + Raw 3종을 합치면 원본 결과 dict와 같음
- 거부 규칙: 같은 (job_id, attempt_id)로 두 번 저장하면 FileExistsError, 원본은 그대로
- 쓰기: 저장 후 임시(.tmp) 파일이 남지 않는다
- 로컬 폴백: job_id/attempt_id 생략 시 local-{해시}/{완료시각 UTC} 경로로 저장된다
"""
import json

import pytest

from l2_scanner.storage import (
    RAW_NAMES,
    build_record,
    files_to_write,
    local_ids,
    save_evidence,
    split_raw,
)


def make_result(**overrides) -> dict:
    result = {
        "schema_version": "1.0",
        "layer": "L2",
        "target": {
            "original_url": "https://example.com/",
            "final_url": "https://example.com/",
            "final_etld1": "example.com",
        },
        "scan": {
            "status": "completed",
            "started_at": "2026-08-31T16:20:00+09:00",
            "finished_at": "2026-08-31T16:20:10+09:00",
        },
        "raw": {
            "http": {"redirect_chain": [], "final_response": {"status_code": 200}},
            "tls": {"hostname": "example.com", "chain_valid": True},
            "ct": {"first_seen": None, "source": None},
        },
        "signals": [
            {"id": "L2-H-01", "scanner": "header", "name": "redirect_chain",
             "detected": False, "evidence": {"redirect_count": 0}},
        ],
        "errors": [],
    }
    result.update(overrides)
    return result


def read_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


class TestSplit:
    def test_record_has_no_raw_but_keeps_everything_else(self):
        result = make_result()
        record = build_record(result)

        assert "raw" not in record
        assert record == {k: v for k, v in result.items() if k != "raw"}

    def test_raw_splits_into_three_collectors(self):
        raws = split_raw(make_result())
        assert set(raws) == set(RAW_NAMES) == {"http", "tls", "ct"}

    def test_missing_raw_tree_is_loud(self):
        # 스키마와 저장 규격이 어긋나면 조용히 파일이 빠지는 게 아니라 KeyError로 드러난다
        broken = make_result(raw={"http": {}, "tls": {}})   # ct 누락
        with pytest.raises(KeyError):
            split_raw(broken)


class TestFilesToWrite:
    def test_paths_follow_team_layout_and_record_is_last(self):
        files = files_to_write(make_result(), job_id="job-1", attempt_id="a-1")
        keys = [key for key, _ in files]

        assert keys[:3] == [
            "raw/job-1/a-1/l2/http.json",
            "raw/job-1/a-1/l2/tls.json",
            "raw/job-1/a-1/l2/ct.json",
        ]
        assert keys[-1] == "records/job-1/a-1/l2.json"


class TestSaveAndRoundtrip:
    def test_saved_files_recombine_into_original_result(self, tmp_path):
        result = make_result()
        saved = save_evidence(result, job_id="job-1", attempt_id="a-1", root=tmp_path)

        record = read_json(saved[-1])
        raws = {name: read_json(path) for name, path in zip(RAW_NAMES, saved[:3])}
        assert {**record, "raw": raws} == result

    def test_korean_preserved_without_escaping(self, tmp_path):
        # ensure_ascii=False - 사람이 읽는 Evidence이므로 한글이 \uXXXX로 깨지면 안 된다
        result = make_result(errors=[{"analyzer": "L2-H-01", "error": "한글 사유"}])
        saved = save_evidence(result, job_id="j", attempt_id="a", root=tmp_path)

        assert "한글 사유" in saved[-1].read_text(encoding="utf-8")

    def test_creates_missing_root_dir(self, tmp_path):
        root = tmp_path / "evidence" / "nested"
        saved = save_evidence(make_result(), job_id="j", attempt_id="a", root=root)
        assert all(path.exists() for path in saved)


class TestLocalIdsFallback:
    def test_default_ids_use_url_digest_and_utc_finished_at(self):
        # 16:20:10+09:00 -> 07:20:10Z (UTC 변환 확인)
        job_id, attempt_id = local_ids(make_result())
        assert job_id.startswith("local-") and len(job_id) == len("local-") + 10
        assert attempt_id == "20260831T072010Z"

    def test_same_time_different_urls_get_different_ids(self):
        a = make_result()
        b = make_result(target={"original_url": "https://other.com/", "final_url": None,
                                "final_etld1": None})
        assert local_ids(a)[0] != local_ids(b)[0]

    def test_unreadable_finished_at_falls_back_to_now(self):
        # 시각을 못 읽어도 id 생성은 실패하지 않는다 (정본 시각은 Record JSON 안에 있음)
        _, attempt_id = local_ids(make_result(scan={"finished_at": None}))
        assert attempt_id.endswith("Z")

    def test_save_without_ids_uses_fallback_paths(self, tmp_path):
        result = make_result()
        saved = save_evidence(result, root=tmp_path)

        job_id, attempt_id = local_ids(result)
        assert saved[-1] == (tmp_path / "records" / job_id / attempt_id / "l2.json").resolve()


class TestRefusalAndAtomicity:
    def test_second_save_with_same_ids_is_refused(self, tmp_path):
        first = save_evidence(make_result(), job_id="j", attempt_id="a", root=tmp_path)
        with pytest.raises(FileExistsError):
            save_evidence(make_result(errors=[{"error": "재시도"}]),
                          job_id="j", attempt_id="a", root=tmp_path)

        assert read_json(first[-1])["errors"] == []   # 먼저 저장된 원본은 그대로

    def test_no_tmp_file_left_behind(self, tmp_path):
        save_evidence(make_result(), job_id="j", attempt_id="a", root=tmp_path)
        assert not list(tmp_path.rglob("*.tmp"))
