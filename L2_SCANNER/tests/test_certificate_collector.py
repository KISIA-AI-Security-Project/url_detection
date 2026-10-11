"""Certificate Collector 파서 단위 테스트.

네트워크 없이, cryptography로 자체 서명 인증서를 즉석 생성해 _parse_certificate를 검증한다.
(실제 handshake 경로는 main.py 라이브 스모크 테스트로 보완)
"""
from datetime import datetime, timedelta, timezone
from contextlib import nullcontext
from types import SimpleNamespace
import pytest
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from l2_scanner.collectors.certificate_collector import _parse_certificate
from l2_scanner.analyzers.certificate import self_signed, hostname_match


def build_self_signed_der(common_name: str, san: list[str],
                          signing_key=None) -> bytes:
    """테스트용 인증서 1장을 DER로 생성한다 (subject == issuer 이름).

    signing_key를 따로 주면 '이름은 자체 서명처럼 꾸몄지만 실제 서명은 다른 키'인
    위장 인증서가 된다 — 서명 실검증 테스트용.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)                      # 자기가 자기를 발급 = 자체 서명 (이름 기준)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=3))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in san]),
            critical=False,
        )
        .sign(signing_key or key, hashes.SHA256())
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

    def test_self_signed_verified_by_signature(self):
        # 자기 키로 서명 + 이름 일치 → 서명 실검증으로 자체 서명 확정 (팀 리뷰 반영)
        assert self.parsed["self_signed"] is True

    def test_forged_issuer_name_fails_signature_check(self):
        # 이름은 subject==issuer로 꾸몄지만 실제 서명은 다른 키 —
        # 문자열 비교라면 자체 서명으로 오인하지만 서명 검증은 걸러낸다
        other_key = ec.generate_private_key(ec.SECP256R1())
        der = build_self_signed_der("fake.local", ["fake.local"], signing_key=other_key)
        parsed = _parse_certificate(der)
        assert parsed["subject"] == parsed["issuer"]    # 이름만 보면 자체 서명처럼 보인다
        assert parsed["self_signed"] is False           # 서명 검증이 위장을 구분

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


@pytest.mark.parametrize('verify', [True, False])
@pytest.mark.parametrize('chain_api', [True, False])
def test_handshake_retains_leaf_on_older_runtime(monkeypatch, verify, chain_api):
    from l2_scanner.collectors import certificate_collector as collector
    tls=SimpleNamespace(getpeercert=lambda **kwargs:b'leaf',version=lambda:'TLSv1.3')
    if chain_api:
        tls.get_verified_chain=lambda:[b'verified']
        tls.get_unverified_chain=lambda:[b'unverified']
    ctx=SimpleNamespace(wrap_socket=lambda *a,**k:nullcontext(tls))
    monkeypatch.setattr(collector.ssl,'create_default_context',lambda:ctx)
    monkeypatch.setattr(collector.socket,'create_connection',lambda *a,**k:nullcontext(object()))
    leaf,chain,version=collector._handshake('8.8.8.8',443,verify)
    assert leaf==b'leaf' and version=='TLSv1.3'
    assert chain==([b'verified' if verify else b'unverified'] if chain_api else None)
    assert ctx.check_hostname is False
    if not verify:assert ctx.verify_mode==ssl.CERT_NONE


@pytest.mark.parametrize('verified', [True, False])
def test_missing_chain_export_preserves_verification_and_leaf(monkeypatch, verified):
    from l2_scanner.collectors import certificate_collector as collector
    der=build_self_signed_der('test.local',['test.local'])
    calls=[]
    def handshake(host,port,verify):
        calls.append(verify)
        if verify and not verified:
            error=ssl.SSLCertVerificationError('untrusted test certificate')
            error.verify_message='untrusted test certificate'
            raise error
        return der,None,'TLSv1.3'
    monkeypatch.setattr(collector,'_handshake',handshake)
    raw=collector.collect('test.local')
    assert raw['leaf_certificate']['san_dns']==['test.local']
    assert raw['chain_valid'] is verified and raw['certificate_chain']==[]
    assert raw['errors'][0]['code']=='tls_chain_export_unavailable'
    assert calls==([True] if verified else [True,False])
