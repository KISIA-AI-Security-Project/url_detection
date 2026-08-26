"""CT Collector 단위 테스트 — httpx.get을 가짜로 바꿔 네트워크 없이 검증.

1차(내장 SCT) 경로는 SCT 목록 주입으로, 2차(crt.sh 폴백) 경로는
crt.sh 실제 응답 형식(JSON 배열, entry_timestamp)을 흉내 낸 가짜 응답으로 재현한다.
(내장 SCT 실측은 main.py 라이브 스모크 — google/naver 인증서에서 SCT 2~3개 확인)
"""
import json

import httpx

from collectors import ct_collector
from collectors.ct_collector import collect, CT_MAX_ATTEMPTS

FINGERPRINT = "ab" * 32


class FakeResponse:
    def __init__(self, status_code: int, text: str = ""):
        self.status_code = status_code
        self.text = text


def crtsh_json(*timestamps) -> str:
    """crt.sh output=json 응답 모양의 항목 배열 (entry_timestamp만 채움)."""
    return json.dumps([{"id": i, "entry_timestamp": ts} for i, ts in enumerate(timestamps)])


def install_fake(monkeypatch, responses: list):
    """httpx.get을 호출 순서대로 responses를 돌려주는 가짜로 바꾸고, 호출 기록을 반환한다.

    responses의 원소가 Exception이면 그 호출에서 예외를 던진다.
    """
    calls = []

    def fake_get(url, params=None, timeout=None):
        calls.append({"url": url, "params": params})
        response = responses[min(len(calls) - 1, len(responses) - 1)]
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(ct_collector.httpx, "get", fake_get)
    return calls


class TestEmbeddedSct:
    def test_sct_used_without_network(self, monkeypatch):
        # 내장 SCT가 있으면 crt.sh를 아예 조회하지 않는다 — 외부 의존 제거가 1차 경로의 목적
        calls = install_fake(monkeypatch, [FakeResponse(200, "[]")])
        result = collect(FINGERPRINT, [
            "2026-08-05T21:44:41.358000+00:00", "2026-08-05T21:44:41.347000+00:00",
        ])
        assert calls == []
        assert result["first_seen"] == "2026-08-05T21:44:41.347000+00:00"   # 최솟값
        assert result["source"] == "embedded_sct"
        assert result["sct_count"] == 2
        assert result["log_entries"] is None    # 조회 안 함
        assert result["errors"] == []

    def test_naive_sct_timestamp_gets_utc(self, monkeypatch):
        # SCT 시각이 오프셋 없이 오더라도 UTC를 부여해 저장한다
        install_fake(monkeypatch, [FakeResponse(200, "[]")])
        result = collect(FINGERPRINT, ["2026-08-05T21:44:41"])
        assert result["first_seen"] == "2026-08-05T21:44:41+00:00"

    def test_no_sct_falls_back_to_crtsh(self, monkeypatch):
        # SCT 없는 인증서(자체 서명·사설) → crt.sh 폴백
        calls = install_fake(monkeypatch, [FakeResponse(200, crtsh_json("2026-08-01T00:00:00"))])
        result = collect(FINGERPRINT, [])
        assert len(calls) == 1
        assert result["first_seen"] == "2026-08-01T00:00:00+00:00"
        assert result["source"] == "crt.sh"
        assert result["sct_count"] == 0


class TestCrtshFallback:
    def test_first_seen_is_earliest_entry_in_utc(self, monkeypatch):
        install_fake(monkeypatch, [FakeResponse(200, crtsh_json(
            "2026-08-02T09:00:00.5", "2026-08-01T10:30:00.123",
        ))])
        result = collect(FINGERPRINT)
        # 최솟값 선택 + 오프셋 없는 시각에 UTC 부여
        assert result["first_seen"] == "2026-08-01T10:30:00.123000+00:00"
        assert result["log_entries"] == 2
        assert result["errors"] == []

    def test_query_uses_fingerprint_and_json_output(self, monkeypatch):
        calls = install_fake(monkeypatch, [FakeResponse(200, crtsh_json("2026-08-01T00:00:00"))])
        collect(FINGERPRINT)
        assert calls[0]["params"] == {"q": FINGERPRINT, "output": "json"}

    def test_null_entry_timestamp_filtered(self, monkeypatch):
        install_fake(monkeypatch, [FakeResponse(200, crtsh_json(None, "2026-08-03T00:00:00"))])
        result = collect(FINGERPRINT)
        assert result["first_seen"] == "2026-08-03T00:00:00+00:00"
        assert result["log_entries"] == 2

    def test_not_in_ct_is_observation_not_error(self, monkeypatch):
        # 빈 배열 = "CT에 없음" — 실패가 아니라 그 자체가 관측 (공인 인증서는 거의 다 CT에 있음)
        install_fake(monkeypatch, [FakeResponse(200, "[]")])
        result = collect(FINGERPRINT)
        assert result["first_seen"] is None
        assert result["log_entries"] == 0
        assert result["errors"] == []


class TestCollectFailure:
    def test_http_error_reported_as_unknown(self, monkeypatch):
        # crt.sh 잦은 장애(502) — 예외 없이 "확인 못 함"(null) + errors 기록
        calls = install_fake(monkeypatch, [FakeResponse(502, "<html>Bad Gateway</html>")])
        result = collect(FINGERPRINT)
        assert result["first_seen"] is None
        assert result["log_entries"] is None
        assert "502" in result["errors"][0]["error"]
        assert len(calls) == CT_MAX_ATTEMPTS   # 재시도까지 소진

    def test_retry_succeeds_after_transient_error(self, monkeypatch):
        install_fake(monkeypatch, [
            FakeResponse(502),
            FakeResponse(200, crtsh_json("2026-08-01T00:00:00")),
        ])
        result = collect(FINGERPRINT)
        assert result["first_seen"] == "2026-08-01T00:00:00+00:00"
        assert result["errors"] == []

    def test_network_exception_recorded(self, monkeypatch):
        install_fake(monkeypatch, [httpx.ConnectError("connection refused")])
        result = collect(FINGERPRINT)
        assert result["first_seen"] is None
        assert "ConnectError" in result["errors"][0]["error"]

    def test_non_json_200_recorded(self, monkeypatch):
        # 200인데 점검 페이지 등 JSON이 아닌 응답
        install_fake(monkeypatch, [FakeResponse(200, "<html>maintenance</html>")])
        result = collect(FINGERPRINT)
        assert result["first_seen"] is None
        assert "parse error" in result["errors"][0]["error"]


class TestNoFingerprint:
    def test_no_lookup_without_fingerprint(self, monkeypatch):
        # 인증서를 못 본 경우 — 조회 자체를 하지 않고 unknown 구조만 (TLS errors에 사유 이미 있음)
        calls = install_fake(monkeypatch, [FakeResponse(200, "[]")])
        result = collect(None)
        assert calls == []
        assert result == {"fingerprint": None, "first_seen": None, "source": None,
                          "sct_count": None, "log_entries": None, "errors": []}
