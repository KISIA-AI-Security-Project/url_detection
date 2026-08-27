"""l2_scanner의 Analyzer 격리 실행(_run_analyzer) 단위 테스트 — 네트워크 없음.

Analyzer 하나가 예상 못 한 Raw Data로 예외를 내도 전체 스캔이 죽지 않고,
해당 기능만 detected null Signal + errors[] 기록으로 대체되는지 확인한다. (팀 리뷰 반영)
"""
from l2_scanner import _run_analyzer
from analyzers.header import redirect_chain


class BrokenAnalyzer:
    """analyze()가 항상 죽는 가짜 Analyzer 모듈."""
    SIGNAL = {"id": "L2-X-99", "scanner": "header", "name": "broken_analyzer"}

    @staticmethod
    def analyze(raw: dict) -> dict:
        raise KeyError("unexpected raw data shape")


class TestRunAnalyzer:
    def test_exception_is_isolated_as_null_signal(self):
        errors = []
        signal = _run_analyzer(BrokenAnalyzer, {}, errors)

        # 실패한 기능은 '검사 불가' Signal로 대체된다 — 스캔 전체를 죽이지 않는다
        assert signal == {
            "id": "L2-X-99", "scanner": "header", "name": "broken_analyzer",
            "detected": None, "evidence": {},
        }
        # 실패 사유는 errors[]에 관측 기록으로 남는다
        assert errors == [{"analyzer": "L2-X-99",
                           "error": "KeyError: 'unexpected raw data shape'"}]

    def test_healthy_analyzer_passes_through(self):
        errors = []
        raw = {
            "original_url": "http://a.com", "final_url": "http://a.com",
            "status_code": 200, "redirect_chain": [],
        }
        signal = _run_analyzer(redirect_chain, raw, errors)

        assert signal["id"] == "L2-H-01"
        assert signal["detected"] is False
        assert errors == []
