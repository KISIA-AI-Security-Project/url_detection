"""L2 Certificate Collector 

[역할]
대상 호스트와 TLS handshake를 1회 수행해 인증서(leaf)와 인증서 체인을 수집, 파싱하고,
Certificate Analyzer들(L2-C-01 ~ 06)이 공유할 Raw Data 딕셔너리로 반환한다.

[전체 overview]
hostname -> [이 Collector: TLS 접속 1회] -> TLS Raw Data -> [Cert Analyzer: 계산만] -> Signals
HTTP Collector와 같은 원칙 - 접속(handshake)은 한 번, 분석은 여러 기능이 공유한다.
X.509 인증서를 한 번 수집한 뒤 notBefore/notAfter/SAN/Subject/Issuer 등을 파싱해 두면 Analyzer들은 파싱된 값만 읽는다.

[2단계 handshake 전략 - 검증 실패해도 관측은 보존]
1차: 체인 검증 ON  (verify_mode=CERT_REQUIRED) -> 성공하면 chain_valid=true + 검증된 체인
2차: 1차가 검증 실패로 끊기면, 검증 OFF(CERT_NONE)로 재접속해 인증서 자체는 수집
-> 자체 서명, 만료 인증서야말로 분석 대상인데, 검증 실패로 인증서를 못 보면 안 됨. 실패 사유는 chain_error에 관측 결과로 남긴다.

호스트명 검사(check_hostname)는 두 번 모두 끈다 - 호스트명 일치는 L2-C-03 Analyzer가SAN을 직접 대조해 판정한다. 
체인 신뢰성(C-05)과 호스트명 일치(C-03)를 분리 관측하기 위함.
"""
import socket
import ssl
from datetime import timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes

from l2_scanner.config.tuning import TLS_TIMEOUT_SECONDS

TLS_DEFAULT_PORT = 443   # 표준 포트 (조정값이 아니라 여기 둔다)


def _parse_certificate(der_bytes: bytes) -> dict:
    """DER 인코딩 인증서 1장을 명세서 6장 leaf_certificate 트리 모양으로 파싱한다.

    반환 필드:
        subject / issuer     - RFC 4514 문자열 (예: "CN=www.google.com,O=Google LLC,...")
        serial_number        - 16진수 문자열
        fingerprint          - 인증서 원문의 sha256 hex (인증서 식별자 — crt.sh 등 조회 열쇠)
        not_before/not_after - ISO 8601 UTC 문자열
        san                  - SubjectAlternativeName의 DNS 이름 + IP 목록
        sct_timestamps       - 내장 SCT(CT 로그 제출 시각) ISO UTC 목록 - L2-C-06의 1차 재료
        self_signed          - 자체 서명 여부 true/false/null (서명을 자기 공개키로 실검증)
    """
    cert = x509.load_der_x509_certificate(der_bytes)

    # SAN(Subject Alternative Name) - 현대 브라우저가 호스트명 대조에 쓰는 유일한 기준.
    # 확장 자체가 없는 인증서(구식, 자체 서명)도 있으므로 없으면 빈 목록.
    san = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san = [str(v) for v in san_ext.value.get_values_for_type(x509.DNSName)]
        san += [str(v) for v in san_ext.value.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        pass

    # 내장 SCT(Signed Certificate Timestamp) 
    # SCT의 timestamp가 CT 로그가 이 인증서를 처음 관측한 시각 - L2-C-06의 1차 재료.
    # (자체 서명, 사설 인증서에는 없다 -> 그때는 CT Collector가 crt.sh 조회로 폴백)
    sct_timestamps = []
    try:
        sct_ext = cert.extensions.get_extension_for_class(
            x509.PrecertificateSignedCertificateTimestamps)
        # SCT timestamp는 오프셋 없는 UTC - tz를 명시해 ISO로 저장
        sct_timestamps = sorted(
            s.timestamp.replace(tzinfo=timezone.utc).isoformat() for s in sct_ext.value)
    except x509.ExtensionNotFound:
        pass

    # 자체 서명 여부 - 이름 비교가 아니라 서명 실검증으로 판정한다:
    # 1. subject != issuer 이름이면 정의상 자체 서명이 아니다.
    # 2. 이름이 같으면 인증서 서명을 자기 공개키로 검증한다 - issuer 이름만 같게 꾸미고
    #    실제로는 다른 키로 서명한 인증서를 이름 비교만으로는 구분 못 하기 때문.
    # 3. 미지원 알고리즘 등으로 검증 자체가 불가하면 null - 확인 안 됨 != 아님
    if cert.subject != cert.issuer:
        self_signed = False
    else:
        try:
            cert.verify_directly_issued_by(cert)   # 이름 일치 + 자기 키 서명 검증
            self_signed = True
        except InvalidSignature:
            self_signed = False       # 이름만 같고 서명은 다른 키 - 자체 서명 아님
        except (ValueError, TypeError):
            self_signed = None        # 알고리즘, 키 유형 미지원 -> 검증 불가(unknown)

    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": format(cert.serial_number, "x"),
        "fingerprint": cert.fingerprint(hashes.SHA256()).hex(),   # sha256 hex
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "san": san,
        "sct_timestamps": sct_timestamps,
        "self_signed": self_signed,
    }


def _handshake(hostname: str, port: int, verify: bool):
    """TLS handshake 1회를 수행하고 (leaf DER, 체인 DER 목록, TLS 버전)을 반환한다.

    verify=True  -> 체인을 OS 신뢰 저장소로 검증 (실패 시 ssl.SSLCertVerificationError)
    verify=False -> 검증 없이 인증서만 수집 (2차 시도용)
    호스트명 검사는 항상 끈다.  L2-C-03 Analyzer의 담당 
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    if not verify:
        ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((hostname, port), timeout=TLS_TIMEOUT_SECONDS) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as tls:  # SNI 전송
            leaf_der = tls.getpeercert(binary_form=True)
            # Python 3.13+: 체인을 DER bytes 목록으로 반환 (leaf 포함, leaf -> 루트 순)
            chain_der = tls.get_verified_chain() if verify else tls.get_unverified_chain()
            return leaf_der, chain_der, tls.version()


def collect(hostname: str, port: int = TLS_DEFAULT_PORT) -> dict:
    """호스트 하나의 TLS 인증서를 관측하고 Raw Data 딕셔너리를 반환한다.

    입력: hostname (SNI로도 사용), port (기본 443)
    출력: TLS 트리 -
          hostname / tls_version / leaf_certificate / certificate_chain[] / chain_valid / chain_error / errors[]

    [오류 처리 - HTTP Collector와 동일]
    handshake 실패, 검증 실패도 예외를 던지지 않고 관측 결과로 기록한다.
    TLS로 확인 못 함(null)과 정상(valid)을 구분해 남기는 것이 목적.
    """
    result = {
        "hostname": hostname,
        "port": port,
        "tls_version": None,
        "leaf_certificate": None,     # 파싱된 인증서 (수집 실패 시 null = 확인 안 됨)
        "certificate_chain": [],      # 서버가 제시한 체인 전체 (leaf 포함, 각각 파싱본)
        "chain_valid": None,          # true/false/null(확인 못 함) - L2-C-05의 재료
        "chain_error": None,          # 검증 실패 사유 원문 (관측 보존)
        "errors": [],
    }

    if not hostname:
        # HTTPS URL이 아예 없었던 경우 - 인증서 관측 자체가 불가 (unknown)
        result["errors"].append({"host": None, "error": "no https target to inspect"})
        return result

    # ---- 1차: 체인 검증 ON ----
    try:
        leaf_der, chain_der, tls_ver = _handshake(hostname, port, verify=True)
        result["chain_valid"] = True

    except ssl.SSLCertVerificationError as e:
        # 검증 실패 = 그 자체가 관측 사실 (자체 서명, 만료, 알 수 없는 CA 등)
        result["chain_valid"] = False
        result["chain_error"] = e.verify_message or str(e)

        # ---- 2차: 검증 OFF로 인증서만 수집 ----
        try:
            leaf_der, chain_der, tls_ver = _handshake(hostname, port, verify=False)
        except (OSError, ssl.SSLError) as e2:
            result["errors"].append({"host": hostname, "error": str(e2)})
            return result

    except (OSError, ssl.SSLError) as e:
        # TLS 자체가 안 되는 경우 (연결 거부, 타임아웃, 프로토콜 오류)
        # chain_valid는 null 유지 — 검증 실패가 아니라 확인 못 함
        result["errors"].append({"host": hostname, "error": str(e)})
        return result

    # ---- 수집된 DER 파싱 (검증 성공/실패 공통 경로) ----
    result["tls_version"] = tls_ver
    try:
        if leaf_der:
            result["leaf_certificate"] = _parse_certificate(leaf_der)
        result["certificate_chain"] = [_parse_certificate(der) for der in chain_der]
    except ValueError as e:
        # DER 파싱 실패 - 원문이 비정상. 실패 사실만 기록 (leaf는 null 유지)
        result["errors"].append({"host": hostname, "error": f"certificate parse error: {e}"})

    return result
