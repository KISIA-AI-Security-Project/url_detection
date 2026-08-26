"""Header Analyzer 8종 단위 테스트 — 가짜 Raw Data 주입, 네트워크 없음."""
from analyzers.header import (
    redirect_chain,
    redirect_domain_change,
    redirect_to_ip,
    url_shortener,
    http_refresh,
    forced_download,
    content_type_mismatch,
    dangerous_file_download,
)


def make_raw(**overrides) -> dict:
    """Collector 출력과 같은 모양의 Raw Data 기본값. 필요한 부분만 덮어쓴다."""
    raw = {
        "original_url": "http://a.com",
        "current_url": "http://a.com",
        "final_url": "http://a.com",
        "status_code": 200,
        "redirect_chain": [],
        "headers": {"content_type": None, "content_disposition": None, "refresh": None},
        "response_body": {"size": None, "detected_type": None, "sha256": None, "truncated": False},
        "download": {"filename": None, "extension": None, "mime_type": None, "magic_bytes": None},
        "errors": [],
    }
    for key, value in overrides.items():
        if isinstance(value, dict):
            raw[key].update(value)
        else:
            raw[key] = value
    return raw


def hop(src, dst, code=302):
    return {"source_url": src, "destination_url": dst, "status_code": code, "location": dst}


# ---------- L2-H-01 redirect_chain ----------

class TestRedirectChain:
    def test_no_redirect(self):
        signal = redirect_chain.analyze(make_raw())
        assert signal["detected"] is False
        assert signal["evidence"]["redirect_count"] == 0

    def test_with_redirects(self):
        raw = make_raw(
            redirect_chain=[hop("http://a.com", "http://b.com"), hop("http://b.com", "http://c.com")],
            final_url="http://c.com",
        )
        signal = redirect_chain.analyze(raw)
        assert signal["detected"] is True
        assert signal["evidence"]["redirect_count"] == 2
        assert signal["evidence"]["chain"] == ["http://b.com", "http://c.com"]


# ---------- L2-H-02 redirect_domain_change ----------

class TestRedirectDomainChange:
    def test_same_owner_subdomain_move_not_counted(self):
        raw = make_raw(
            original_url="http://login.example.com",
            redirect_chain=[hop("http://login.example.com", "http://pay.example.com")],
            final_url="http://pay.example.com",
        )
        signal = redirect_domain_change.analyze(raw)
        assert signal["detected"] is False
        assert signal["evidence"]["final_domain_changed"] is False

    def test_owner_change_counted(self):
        raw = make_raw(
            original_url="http://example.com",
            redirect_chain=[
                hop("http://example.com", "http://short.example.net/a"),
                hop("http://short.example.net/a", "http://login.example.xyz"),
            ],
            final_url="http://login.example.xyz",
        )
        evidence = redirect_domain_change.analyze(raw)["evidence"]
        assert evidence["domain_change_count"] == 2
        assert evidence["unique_domain_count"] == 3
        assert evidence["final_domain_changed"] is True


# ---------- L2-H-03 redirect_to_ip ----------

class TestRedirectToIp:
    def test_ip_destination(self):
        raw = make_raw(redirect_chain=[hop("http://a.com", "http://93.184.216.34/")])
        evidence = redirect_to_ip.analyze(raw)["evidence"]
        assert evidence["destination_ip"] == "93.184.216.34"

    def test_port_is_stripped(self):
        raw = make_raw(redirect_chain=[hop("http://a.com", "http://192.0.2.10:8080/")])
        assert redirect_to_ip.analyze(raw)["evidence"]["destination_ip"] == "192.0.2.10"

    def test_domain_only(self):
        raw = make_raw(redirect_chain=[hop("http://a.com", "http://b.com")])
        signal = redirect_to_ip.analyze(raw)
        assert signal["detected"] is False
        assert signal["evidence"]["destination_ip"] is None


# ---------- L2-H-04 url_shortener ----------

class TestUrlShortener:
    def test_resolved_shortener(self):
        raw = make_raw(
            original_url="https://tinyurl.com/x",
            redirect_chain=[hop("https://tinyurl.com/x", "https://example.com/")],
            final_url="https://example.com/",
        )
        evidence = url_shortener.analyze(raw)["evidence"]
        assert evidence["shortener_domain"] == "tinyurl.com"
        assert evidence["resolved_url"] == "https://example.com/"

    def test_dead_short_link(self):
        # 리다이렉트가 안 풀린 죽은 링크 — 사용은 관측, 목적지는 unknown
        raw = make_raw(original_url="https://bit.ly/dead", final_url="https://bit.ly/dead")
        signal = url_shortener.analyze(raw)
        assert signal["detected"] is True
        assert signal["evidence"]["resolved_url"] is None

    def test_subdomain_of_shortener(self):
        raw = make_raw(
            original_url="https://api.bit.ly/x",
            redirect_chain=[hop("https://api.bit.ly/x", "https://example.com/")],
            final_url="https://example.com/",
        )
        assert url_shortener.analyze(raw)["detected"] is True


# ---------- L2-H-05 content_type_mismatch ----------

class TestContentTypeMismatch:
    def test_mismatch(self):
        raw = make_raw(
            headers={"content_type": "image/png; charset=x"},
            response_body={"detected_type": "text/plain"},
        )
        signal = content_type_mismatch.analyze(raw)
        assert signal["detected"] is True
        assert signal["evidence"]["declared_type"] == "image/png"

    def test_equivalent_pair_not_flagged(self):
        raw = make_raw(
            headers={"content_type": "application/json"},
            response_body={"detected_type": "text/plain"},
        )
        assert content_type_mismatch.analyze(raw)["detected"] is False

    def test_unknown_is_not_mismatch(self):
        assert content_type_mismatch.analyze(make_raw())["detected"] is False


# ---------- L2-H-06 dangerous_file_download ----------

class TestDangerousFileDownload:
    def test_dangerous_extension(self):
        raw = make_raw(download={"filename": "report.exe", "extension": "exe"})
        assert dangerous_file_download.analyze(raw)["detected"] is True

    def test_executable_magic_with_disguised_name(self):
        raw = make_raw(
            download={"filename": "photo.jpg", "extension": "jpg"},
            response_body={"detected_type": "application/x-dosexec"},
        )
        assert dangerous_file_download.analyze(raw)["detected"] is True

    def test_direct_link_script_detected_via_url_extension(self):
        # 직링크 ps1: Collector가 URL 경로에서 extension을 채워주는 전제의 회귀 테스트
        raw = make_raw(
            original_url="http://evil.example/payload.ps1",
            final_url="http://evil.example/payload.ps1",
            headers={"content_type": "text/plain"},
            response_body={"detected_type": "text/plain", "size": 100, "sha256": "abc"},
            download={"filename": "payload.ps1", "extension": "ps1", "mime_type": "text/plain"},
        )
        assert dangerous_file_download.analyze(raw)["detected"] is True

    def test_benign_page(self):
        raw = make_raw(response_body={"detected_type": "text/html"})
        assert dangerous_file_download.analyze(raw)["detected"] is False


# ---------- L2-H-07 forced_download ----------

class TestForcedDownload:
    def test_attachment(self):
        raw = make_raw(headers={"content_disposition": 'attachment; filename="report.exe"'})
        signal = forced_download.analyze(raw)
        assert signal["detected"] is True
        assert signal["evidence"]["extension"] == "exe"

    def test_rfc5987_filename_star(self):
        raw = make_raw(
            headers={"content_disposition": "attachment; filename*=UTF-8''%EC%95%85%EC%84%B1.exe"}
        )
        evidence = forced_download.analyze(raw)["evidence"]
        assert evidence["filename"] == "악성.exe"
        assert evidence["extension"] == "exe"

    def test_inline_not_forced_but_filename_kept(self):
        raw = make_raw(headers={"content_disposition": 'inline; filename="doc.pdf"'})
        signal = forced_download.analyze(raw)
        assert signal["detected"] is False
        assert signal["evidence"]["filename"] == "doc.pdf"

    def test_attachment_without_filename(self):
        raw = make_raw(headers={"content_disposition": "attachment"})
        signal = forced_download.analyze(raw)
        assert signal["detected"] is True
        assert signal["evidence"]["filename"] is None

    def test_no_header(self):
        assert forced_download.analyze(make_raw())["detected"] is False


# ---------- L2-H-08 http_refresh ----------

class TestHttpRefresh:
    def test_semicolon_form(self):
        raw = make_raw(headers={"refresh": "5; url=https://example.com"})
        evidence = http_refresh.analyze(raw)["evidence"]
        assert evidence == {"target_url": "https://example.com", "delay_seconds": 5}

    def test_comma_form(self):
        # 브라우저가 허용하는 콤마 구분자 — 회피 통로 회귀 테스트
        raw = make_raw(headers={"refresh": "0,url=http://evil.example/x"})
        evidence = http_refresh.analyze(raw)["evidence"]
        assert evidence == {"target_url": "http://evil.example/x", "delay_seconds": 0}

    def test_fractional_delay(self):
        raw = make_raw(headers={"refresh": "5.5; url=http://b.com"})
        assert http_refresh.analyze(raw)["evidence"]["delay_seconds"] == 5.5

    def test_uppercase_url_key_and_quotes(self):
        raw = make_raw(headers={"refresh": "3; URL='http://b.com'"})
        assert http_refresh.analyze(raw)["evidence"]["target_url"] == "http://b.com"

    def test_relative_url_absolutized(self):
        raw = make_raw(final_url="http://a.com/page", headers={"refresh": "0; url=/next"})
        assert http_refresh.analyze(raw)["evidence"]["target_url"] == "http://a.com/next"

    def test_self_refresh_without_url(self):
        raw = make_raw(headers={"refresh": "5"})
        signal = http_refresh.analyze(raw)
        assert signal["detected"] is True
        assert signal["evidence"] == {"target_url": None, "delay_seconds": 5}

    def test_non_numeric_delay(self):
        raw = make_raw(headers={"refresh": "abc; url=http://b.com"})
        evidence = http_refresh.analyze(raw)["evidence"]
        assert evidence["delay_seconds"] is None
        assert evidence["target_url"] == "http://b.com"

    def test_no_header(self):
        assert http_refresh.analyze(make_raw())["detected"] is False
