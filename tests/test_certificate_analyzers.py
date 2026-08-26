"""Certificate Analyzer 6종 단위 테스트 — 가짜 TLS·CT Raw Data 주입, 네트워크 없음."""
from datetime import datetime, timedelta, timezone

from analyzers.certificate import (
    certificate_age,
    certificate_validity,
    hostname_match,
    self_signed,
    certificate_chain,
    ct_first_seen,
)


def days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def days_later(days: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


def make_tls(**overrides) -> dict:
    """Certificate Collector 출력과 같은 모양의 TLS Raw Data 기본값.

    기본값 = 정상 인증서 (발급 1년 경과, 90일 남음, SAN 일치, CA 발급, 체인 유효)
    """
    tls = {
        "hostname": "www.example.com",
        "port": 443,
        "tls_version": "TLSv1.3",
        "leaf_certificate": {
            "subject": "CN=www.example.com,O=Example Inc",
            "issuer": "CN=Example CA,O=CA Corp",
            "serial_number": "ab12",
            "fingerprint": "f" * 64,
            "not_before": days_ago(365),
            "not_after": days_later(90),
            "san": ["www.example.com", "example.com"],
            "sct_timestamps": [days_ago(365)],
        },
        "certificate_chain": [{"subject": "leaf"}, {"subject": "intermediate"}, {"subject": "root"}],
        "chain_valid": True,
        "chain_error": None,
        "errors": [],
    }
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(tls.get(key), dict):
            tls[key].update(value)
        else:
            tls[key] = value
    return tls


def no_tls() -> dict:
    """HTTPS 대상이 없거나 handshake 실패로 인증서를 못 본 경우."""
    return make_tls(
        hostname=None, tls_version=None, leaf_certificate=None,
        certificate_chain=[], chain_valid=None, chain_error=None,
    )


# ---------- L2-C-01 certificate_age ----------

class TestCertificateAge:
    def test_old_certificate_not_fresh(self):
        signal = certificate_age.analyze(make_tls())
        assert signal["detected"] is False
        assert signal["evidence"]["age_days"] >= 364
        assert signal["evidence"]["fresh"] is False

    def test_fresh_certificate(self):
        signal = certificate_age.analyze(make_tls(leaf_certificate={"not_before": days_ago(2)}))
        assert signal["detected"] is True
        assert signal["evidence"] == {"age_days": 2, "fresh": True}

    def test_unknown_when_no_certificate(self):
        signal = certificate_age.analyze(no_tls())
        assert signal["detected"] is False
        assert signal["evidence"] == {"age_days": None, "fresh": None}

    def test_future_not_before_is_not_fresh(self):
        # notBefore가 미래(음수 age) = '최근 발급'이 아니라 not_yet_valid(C-02)의 영역
        tls = make_tls(leaf_certificate={"not_before": days_later(3)})
        signal = certificate_age.analyze(tls)
        assert signal["detected"] is False
        assert signal["evidence"]["fresh"] is False


# ---------- L2-C-02 certificate_validity ----------

class TestCertificateValidity:
    def test_valid(self):
        signal = certificate_validity.analyze(make_tls())
        assert signal["detected"] is False
        assert signal["evidence"]["status"] == "valid"

    def test_expired(self):
        tls = make_tls(leaf_certificate={"not_before": days_ago(400), "not_after": days_ago(5)})
        signal = certificate_validity.analyze(tls)
        assert signal["detected"] is True
        assert signal["evidence"]["status"] == "expired"

    def test_not_valid_when_not_before_is_future(self):
        tls = make_tls(leaf_certificate={"not_before": days_later(1), "not_after": days_later(90)})
        signal = certificate_validity.analyze(tls)
        assert signal["detected"] is True
        assert signal["evidence"]["status"] == "not_valid"   # 팀 표기 (노션 L2-C-02 정의)

    def test_unknown_when_no_certificate(self):
        signal = certificate_validity.analyze(no_tls())
        assert signal["detected"] is False
        assert signal["evidence"]["status"] is None


# ---------- L2-C-03 hostname_match ----------

class TestHostnameMatch:
    def test_signal_name_matches_notion_spec(self):
        # 노션 L2-C-03 페이지의 Signal 예시와 동일한 name이어야 한다
        assert hostname_match.analyze(make_tls())["name"] == "hostname_certificate_match"

    def test_exact_san_match(self):
        signal = hostname_match.analyze(make_tls())
        assert signal["detected"] is False
        assert signal["evidence"]["matched"] is True
        assert signal["evidence"]["matched_name"] == "www.example.com"

    def test_wildcard_matches_single_label(self):
        tls = make_tls(hostname="login.example.com",
                       leaf_certificate={"san": ["*.example.com"]})
        assert hostname_match.analyze(tls)["evidence"]["matched"] is True

    def test_wildcard_does_not_match_two_labels(self):
        tls = make_tls(hostname="a.b.example.com",
                       leaf_certificate={"san": ["*.example.com"]})
        signal = hostname_match.analyze(tls)
        assert signal["detected"] is True
        assert signal["evidence"]["matched"] is False

    def test_wildcard_does_not_match_bare_domain(self):
        tls = make_tls(hostname="example.com",
                       leaf_certificate={"san": ["*.example.com"]})
        assert hostname_match.analyze(tls)["evidence"]["matched"] is False

    def test_mismatch_detected(self):
        tls = make_tls(hostname="phish.evil.xyz")
        signal = hostname_match.analyze(tls)
        assert signal["detected"] is True
        assert signal["evidence"]["matched"] is False

    def test_cn_fallback_when_no_san(self):
        tls = make_tls(leaf_certificate={"san": []})   # 구식 인증서 — CN만 있음
        signal = hostname_match.analyze(tls)
        assert signal["evidence"]["matched"] is True
        assert signal["evidence"]["matched_name"] == "www.example.com"

    def test_case_insensitive(self):
        tls = make_tls(hostname="WWW.Example.COM")
        assert hostname_match.analyze(tls)["evidence"]["matched"] is True

    def test_unknown_when_no_certificate(self):
        signal = hostname_match.analyze(no_tls())
        assert signal["detected"] is False
        assert signal["evidence"]["matched"] is None


# ---------- L2-C-04 self_signed ----------

class TestSelfSigned:
    def test_ca_issued_not_detected(self):
        assert self_signed.analyze(make_tls())["detected"] is False

    def test_self_signed_detected(self):
        same = "CN=myserver,O=Home"
        tls = make_tls(leaf_certificate={"subject": same, "issuer": same})
        signal = self_signed.analyze(tls)
        assert signal["detected"] is True
        assert signal["evidence"]["subject"] == signal["evidence"]["issuer"]

    def test_unknown_when_no_certificate(self):
        signal = self_signed.analyze(no_tls())
        assert signal["detected"] is False
        assert signal["evidence"] == {"subject": None, "issuer": None}


# ---------- L2-C-05 certificate_chain ----------

class TestCertificateChain:
    def test_valid_chain(self):
        signal = certificate_chain.analyze(make_tls())
        assert signal["detected"] is False
        assert signal["evidence"] == {"valid": True, "chain_depth": 3, "error": None}

    def test_invalid_chain_detected(self):
        tls = make_tls(chain_valid=False,
                       chain_error="self-signed certificate",
                       certificate_chain=[{"subject": "leaf"}])
        signal = certificate_chain.analyze(tls)
        assert signal["detected"] is True
        assert signal["evidence"] == {
            "valid": False, "chain_depth": 1, "error": "self-signed certificate",
        }

    def test_unknown_when_tls_failed(self):
        signal = certificate_chain.analyze(no_tls())
        assert signal["detected"] is False
        assert signal["evidence"] == {"valid": None, "chain_depth": None, "error": None}


# ---------- L2-C-06 ct_first_seen ----------

def make_ct(**overrides) -> dict:
    """CT Collector 출력과 같은 모양의 CT Raw Data 기본값 (1년 전 관측 = 정상 인증서)."""
    ct = {
        "fingerprint": "f" * 64,
        "first_seen": days_ago(365),
        "source": "embedded_sct",
        "sct_count": 2,
        "log_entries": None,
        "errors": [],
    }
    ct.update(overrides)
    return ct


class TestCtFirstSeen:
    def test_old_first_seen_not_fresh(self):
        signal = ct_first_seen.analyze(make_ct())
        assert signal["detected"] is False
        assert signal["evidence"]["age_days"] >= 364
        assert signal["evidence"]["fresh"] is False

    def test_fresh_first_seen_detected(self):
        signal = ct_first_seen.analyze(make_ct(first_seen=days_ago(2)))
        assert signal["detected"] is True
        assert signal["evidence"]["age_days"] == 2
        assert signal["evidence"]["fresh"] is True

    def test_unknown_when_lookup_failed(self):
        # SCT 없음 + crt.sh 조회 실패 — unknown ≠ fresh, evidence는 정직하게 null
        signal = ct_first_seen.analyze(make_ct(
            first_seen=None, source=None, sct_count=0, log_entries=None,
            errors=[{"host": "crt.sh", "error": "crt.sh returned HTTP 502"}],
        ))
        assert signal["detected"] is False
        assert signal["evidence"] == {"first_seen": None, "age_days": None, "fresh": None}

    def test_not_in_ct_reports_unknown_age(self):
        # SCT 없음 + crt.sh 조회는 성공했으나 CT에 없음 — first_seen이 없으니 age는 unknown
        signal = ct_first_seen.analyze(make_ct(
            first_seen=None, source=None, sct_count=0, log_entries=0))
        assert signal["detected"] is False
        assert signal["evidence"] == {"first_seen": None, "age_days": None, "fresh": None}

    def test_future_first_seen_is_not_fresh(self):
        # 미래 시각(음수 age)은 시계 오차·이상 데이터 — fresh로 치지 않는다 (C-01과 동일 규칙)
        signal = ct_first_seen.analyze(make_ct(first_seen=days_later(3)))
        assert signal["detected"] is False
        assert signal["evidence"]["fresh"] is False
