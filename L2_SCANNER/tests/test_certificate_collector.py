"""Certificate Collector 파서 단위 테스트.

네트워크 없이, cryptography로 자체 서명 인증서를 즉석 생성해 _parse_certificate를 검증한다.
(실제 handshake 경로는 main.py 라이브 스모크 테스트로 보완)
"""
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from collectors.certificate_collector import _parse_certificate
from analyzers.certificate import self_signed, hostname_match


def build_self_signed_der(common_name: str, san: list[str]) -> bytes:
    """테스트용 자체 서명 인증서 1장을 DER로 생성한다 (subject == issuer)."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)                      # 자기가 자기를 발급 = 자체 서명
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=3))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in san]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.DER)


class TestParseCertificate:
    def setup_method(self):
        der = build_self_signed_der("test.local", ["test.local", "alt.test.local"])
        self.parsed = _parse_certificate(der)

    def test_subject_and_issuer(self):
        assert "CN=test.local" in self.parsed["subject"]
        assert self.parsed["subject"] == self.parsed["issuer"]   # 자체 서명

    def test_san_extracted(self):
        assert self.parsed["san"] == ["test.local", "alt.test.local"]

    def test_validity_fields_are_iso(self):
        # ISO 문자열로 저장되어 Analyzer가 fromisoformat으로 읽을 수 있어야 한다
        assert datetime.fromisoformat(self.parsed["not_before"]) < datetime.now(timezone.utc)
        assert datetime.fromisoformat(self.parsed["not_after"]) > datetime.now(timezone.utc)

    def test_fingerprint_is_sha256_hex(self):
        assert len(self.parsed["fingerprint"]) == 64

    def test_no_sct_extension_gives_empty_list(self):
        # 자체 서명 인증서에는 내장 SCT가 없다 → 빈 목록 (CT Collector가 crt.sh 폴백으로 감)
        assert self.parsed["sct_timestamps"] == []

    def test_feeds_self_signed_analyzer(self):
        # 파서 출력 → Analyzer 입력의 통합 경로 확인
        tls = {
            "hostname": "test.local",
            "leaf_certificate": self.parsed,
            "certificate_chain": [self.parsed],
            "chain_valid": False,
            "chain_error": "self-signed certificate",
            "errors": [],
        }
        assert self_signed.analyze(tls)["detected"] is True
        assert hostname_match.analyze(tls)["evidence"]["matched"] is True
