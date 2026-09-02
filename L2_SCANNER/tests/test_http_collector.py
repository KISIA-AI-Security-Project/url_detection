"""HTTP Collector 순수 함수(네트워크 무관 부분) 단위 테스트."""
from l2_scanner.collectors.http_collector import _blocked_destination


class TestBlockedDestination:
    def test_loopback_blocked(self):
        assert _blocked_destination("http://127.0.0.1/") is not None

    def test_private_blocked(self):
        assert _blocked_destination("http://192.168.0.10:8080/admin") is not None

    def test_aws_metadata_blocked(self):
        assert _blocked_destination("http://169.254.169.254/latest/meta-data/") is not None

    def test_public_ip_allowed(self):
        assert _blocked_destination("http://93.184.216.34/") is None

    def test_hostless_url_allowed(self):
        # 호스트가 없는 비정상 URL은 여기서 차단하지 않는다 (접속 단계에서 자연 실패)
        assert _blocked_destination("not-a-url") is None
