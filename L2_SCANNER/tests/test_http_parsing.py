"""utils/http_parsing 공용 유틸 단위 테스트 — 네트워크 없음."""
from utils.http_parsing import (
    parse_content_disposition,
    extension_from_filename,
    filename_from_url,
    split_mime,
    etld1,
)


class TestParseContentDisposition:
    def test_basic_attachment(self):
        parsed = parse_content_disposition('attachment; filename="report.exe"')
        assert parsed == {"type": "attachment", "filename": "report.exe"}

    def test_uppercase_tokens(self):
        parsed = parse_content_disposition('Attachment; FILENAME="mal.exe"')
        assert parsed == {"type": "attachment", "filename": "mal.exe"}

    def test_single_quotes(self):
        parsed = parse_content_disposition("attachment; filename='a.exe'")
        assert parsed["filename"] == "a.exe"

    def test_rfc5987_filename_star(self):
        # RFC 5987: filename*=charset''percent-encoded — "악성.exe"
        parsed = parse_content_disposition(
            "attachment; filename*=UTF-8''%EC%95%85%EC%84%B1.exe"
        )
        assert parsed["filename"] == "악성.exe"

    def test_filename_star_wins_over_filename(self):
        # RFC 6266: filename*이 filename보다 우선
        parsed = parse_content_disposition(
            "attachment; filename=\"decoy.txt\"; filename*=UTF-8''real.exe"
        )
        assert parsed["filename"] == "real.exe"

    def test_attachment_without_filename(self):
        parsed = parse_content_disposition("attachment")
        assert parsed == {"type": "attachment", "filename": None}

    def test_inline(self):
        parsed = parse_content_disposition('inline; filename="doc.pdf"')
        assert parsed["type"] == "inline"

    def test_unknown_charset_falls_back(self):
        parsed = parse_content_disposition("attachment; filename*=X-BAD''a%20b.exe")
        assert parsed["filename"] == "a b.exe"


class TestExtensionFromFilename:
    def test_basic(self):
        assert extension_from_filename("report.EXE") == "exe"

    def test_double_extension_takes_last(self):
        assert extension_from_filename("invoice.pdf.exe") == "exe"

    def test_no_dot(self):
        assert extension_from_filename("README") is None

    def test_none(self):
        assert extension_from_filename(None) is None


class TestFilenameFromUrl:
    def test_direct_file_link(self):
        assert filename_from_url("http://evil.example/payload.ps1") == "payload.ps1"

    def test_percent_encoded(self):
        assert filename_from_url("http://x/%EC%95%85%EC%84%B1.exe") == "악성.exe"

    def test_page_path_without_extension(self):
        assert filename_from_url("http://x/search") is None

    def test_root(self):
        assert filename_from_url("https://www.google.com/") is None

    def test_query_ignored(self):
        assert filename_from_url("http://x/a.exe?token=1.2") == "a.exe"


class TestSplitMime:
    def test_strips_params_and_lowers(self):
        assert split_mime("Text/HTML; charset=UTF-8") == "text/html"

    def test_none(self):
        assert split_mime(None) is None


class TestEtld1:
    def test_public_suffix(self):
        assert etld1("https://login.example.co.kr/a") == "example.co.kr"

    def test_ip_host(self):
        assert etld1("http://93.184.216.34/") == "93.184.216.34"
