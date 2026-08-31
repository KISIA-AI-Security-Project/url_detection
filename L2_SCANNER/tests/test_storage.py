"""storage.save_record 테스트. 가짜 결과 dict를 저장하고 파일을 검증한다 (네트워크 없음).

검증 대상 (모듈 설계 원칙 그대로):
- 저장, 라운드트립: JSON으로 저장한 것을 읽으면 원본 dict와 같다 (한글 포함)
- 파일명 규칙: 완료 시각(UTC 변환) + URL 해시
- 원본 보존: 같은 이름이 있으면 덮어쓰지 않고 순번 파일 생성
- 원자적 쓰기: 저장 후 임시(.tmp) 파일이 남지 않는다
"""
import json

from l2_scanner.storage import save_record, default_filename


def make_result(**overrides) -> dict:
    """scan() 결과의 최소 골격 - 필요한 필드만 덮어써서 상황을 만든다."""
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
        "raw": {"http": {}, "tls": {}, "ct": {}},
        "signals": [
            {"id": "L2-H-01", "scanner": "header", "name": "redirect_chain",
             "detected": False, "evidence": {"redirect_count": 0}},
        ],
        "errors": [],
    }
    result.update(overrides)
    return result


class TestSaveAndRoundtrip:
    def test_saves_json_that_reads_back_identical(self, tmp_path):
        result = make_result()
        path = save_record(result, output_dir=tmp_path)

        assert path.exists()
        with open(path, encoding="utf-8") as f:
            assert json.load(f) == result

    def test_korean_preserved_without_escaping(self, tmp_path):
        # ensure_ascii=False - 사람이 읽는 Evidence이므로 한글이 \uXXXX로 깨지면 안 된다
        result = make_result(errors=[{"analyzer": "L2-H-01", "error": "한글 사유"}])
        path = save_record(result, output_dir=tmp_path)

        assert "한글 사유" in path.read_text(encoding="utf-8")

    def test_creates_missing_output_dir(self, tmp_path):
        target = tmp_path / "records" / "nested"
        path = save_record(make_result(), output_dir=target)
        assert path.parent == target.resolve()


class TestFilenameRule:
    def test_default_name_uses_utc_finished_at_and_url_digest(self):
        # 16:20:10+09:00 -> 07:20:10Z (UTC 변환 확인)
        name = default_filename(make_result())
        assert name.startswith("l2_20260831T072010Z_")
        assert name.endswith(".json")

    def test_same_time_different_urls_get_different_names(self):
        a = make_result()
        b = make_result(target={"original_url": "https://other.com/", "final_url": None,
                                "final_etld1": None})
        assert default_filename(a) != default_filename(b)

    def test_unreadable_finished_at_falls_back_to_now(self):
        # 시각을 못 읽어도 파일명 생성은 실패하지 않는다 (정본 시각은 JSON 안에 있음)
        name = default_filename(make_result(scan={"finished_at": None}))
        assert name.startswith("l2_") and name.endswith(".json")

    def test_explicit_filename_overrides_default(self, tmp_path):
        path = save_record(make_result(), output_dir=tmp_path, filename="custom.json")
        assert path.name == "custom.json"


class TestPreservationAndAtomicity:
    def test_existing_file_is_not_overwritten(self, tmp_path):
        first = save_record(make_result(), output_dir=tmp_path)
        second = save_record(make_result(errors=[{"error": "재시도"}]), output_dir=tmp_path)

        assert first != second                      # 순번이 붙은 새 파일
        assert second.stem == first.stem + "-1"
        with open(first, encoding="utf-8") as f:
            assert json.load(f)["errors"] == []     # 먼저 저장된 원본은 그대로

    def test_no_tmp_file_left_behind(self, tmp_path):
        save_record(make_result(), output_dir=tmp_path)
        assert not list(tmp_path.glob("*.tmp"))
