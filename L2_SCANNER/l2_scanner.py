"""L2 Scanner 진입점

[처리 흐름]
    scan(url)
      1. HTTP Collector가 접속 1회로 HTTP Raw Data 수집  (collectors/http_collector.py)
      2. Certificate Collector가 TLS handshake 1회로 인증서 수집 (collectors/certificate_collector.py) - 대상 호스트는 HTTPS URL(최종 도착 우선, 없으면 원본)에서 결정
      3. CT Collector가 CT 최초 관측 시각 수집 (collectors/ct_collector.py) - 내장 SCT 우선(접속 없음), SCT 없는 인증서만 crt.sh 폴백 조회
      4. Header Analyzer 8종 + Certificate Analyzer 6종이 Raw Data를 공유해 Signal 생성 (Analyzer는 네트워크 재접속 없음. C-06만 CT Raw Data를 읽는다)
      5. JSON(dict)으로 조립해 반환

[아직 비어 있는 자리 — 의도된 placeholder]
- job_id·attempt_id 등 시스템 공통 식별자: Evidence 스키마 팀 확정 후 덧붙인다.
- scan.status의 세분화(PARTIAL/BLOCKED 등): 상태 Enum 팀 확정 대기.
"""
from datetime import datetime
from urllib.parse import urlsplit

from collectors.http_collector import collect
from collectors.certificate_collector import collect as collect_certificate, TLS_DEFAULT_PORT
from collectors.ct_collector import collect as collect_ct
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
from analyzers.certificate import (
    certificate_age,
    certificate_validity,
    hostname_match,
    self_signed,
    certificate_chain,
    ct_first_seen,
)
from utils.http_parsing import etld1

SCHEMA_VERSION = "1.0"

# 기능 번호(L2-H-01~08) 순서 - 결과 JSON의 signals[]도 이 순서로 출력된다
HEADER_ANALYZERS = [
    redirect_chain,           # L2-H-01
    redirect_domain_change,   # L2-H-02
    redirect_to_ip,           # L2-H-03
    url_shortener,            # L2-H-04
    content_type_mismatch,    # L2-H-05
    dangerous_file_download,  # L2-H-06
    forced_download,          # L2-H-07
    http_refresh,             # L2-H-08
]

# C-06(ct_first_seen)은 이 목록에 없다 - TLS가 아닌 CT Raw Data를 읽으므로 scan()에서 따로 호출
CERTIFICATE_ANALYZERS = [
    certificate_age,
    certificate_validity,
    hostname_match,
    self_signed,
    certificate_chain,
]


def _now_iso() -> str:
    """로컬 타임존이 붙은 ISO 8601 시각 (예시: 2026-08-24T09:20:10+09:00)"""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _run_analyzer(analyzer, raw: dict, errors: list) -> dict:
    """Analyzer 1개를 격리 실행한다 - 하나가 죽어도 전체 스캔은 계속된다. 

    Analyzer가 예상 못 한 Raw Data로 예외를 내면, 이미 수집한 관측과 나머지 Signal까지
    전부 잃는 것이 기존 동작이었다. 검증 실패해도 관측은 보존에 따라
    실패한 기능만 detected null(검사 불가) Signal로 대체하고 사유를 errors[]에 남긴다.
    각 Analyzer 모듈의 SIGNAL 상수(id/scanner/name)가 대체 Signal의 뼈대가 된다.
    """
    try:
        return analyzer.analyze(raw)
    except Exception as e:
        errors.append({
            "analyzer": analyzer.SIGNAL["id"],
            "error": f"{type(e).__name__}: {e}",
        })
        return {**analyzer.SIGNAL, "detected": None, "evidence": {}}


def _tls_target(raw_http: dict) -> tuple[str | None, int]:
    """인증서를 관측할 (호스트, 포트)를 정한다.

    우선순위: 1. 최종 도착 URL이 https면 그 호스트 - 사용자가 실제로 도달하는 지점의인증서가 분석 대상. 
             2. 최종 응답을 못 받았으면 원본 URL이 https일 때 그 호스트.
    둘 다 https가 아니면 (None, 기본 포트) - 인증서 관측 불가(unknown)로 처리된다.
    """
    for candidate in (raw_http["final_url"], raw_http["original_url"]):
        if not candidate:
            continue
        parts = urlsplit(candidate)
        try:
            port = parts.port   # 포트 표기가 비정상이면(":abc") ValueError
        except ValueError:
            continue
        if parts.scheme == "https" and parts.hostname:
            return parts.hostname, port or TLS_DEFAULT_PORT
    return None, TLS_DEFAULT_PORT


def scan(url: str) -> dict:
    """URL 하나를 관측, 분석하고 L2 결과를 반환한다."""
    started_at = _now_iso()

    # 1. HTTP 수집 (접속 1회)
    raw_http = collect(url)

    # 2. TLS 인증서 수집 (handshake 1회) - HTTPS 대상이 없으면 unknown 구조로 남는다
    tls_host, tls_port = _tls_target(raw_http)
    raw_tls = collect_certificate(tls_host, tls_port)

    # 3. CT 최초 관측 수집 - 내장 SCT 우선(접속 없음), 없으면 crt.sh 폴백 조회
    leaf = raw_tls["leaf_certificate"]
    raw_ct = collect_ct(
        leaf["fingerprint"] if leaf else None,
        leaf["sct_timestamps"] if leaf else None,
    )

    # 4. 분석 - Analyzer는 네트워크 접속 없이 Raw Data만 읽는다.
    # 각 Analyzer는 격리 실행된다 - 하나가 예외로 죽어도 나머지 Signal과 관측은 보존
    analyzer_errors: list = []
    signals = [_run_analyzer(a, raw_http, analyzer_errors) for a in HEADER_ANALYZERS]
    signals += [_run_analyzer(a, raw_tls, analyzer_errors) for a in CERTIFICATE_ANALYZERS]
    signals += [_run_analyzer(ct_first_seen, raw_ct, analyzer_errors)]   # C-06만 CT Raw Data를 읽는다

    finished_at = _now_iso()

    final_url = raw_http["final_url"]

    # 5. 결과 조립
    return {
        "schema_version": SCHEMA_VERSION,
        "layer": "L2",

        "target": {
            "original_url": raw_http["original_url"],
            "final_url": final_url,
            # 최종 응답을 못 받았으면 unknown(null) - 확인 안 됨과 없음의 구분
            "final_etld1": etld1(final_url) if final_url else None,
        },

        "scan": {
            # 최종 응답 확보 여부 기준. 상태 Enum(PARTIAL/BLOCKED 등)은 팀 확정 후 세분화
            "status": "completed" if raw_http["status_code"] is not None else "failed",
            "started_at": started_at,
            "finished_at": finished_at,
        },

        "raw": {
            "http": {
                "redirect_chain": raw_http["redirect_chain"],
                "final_response": {
                    "url": final_url,
                    "status_code": raw_http["status_code"],
                    "headers": raw_http["headers"],
                    "response_body": raw_http["response_body"],
                },
                "download": raw_http["download"],
            },
            # TLS 트리 - Certificate Collector의 관측 결과
            "tls": {
                "hostname": raw_tls["hostname"],
                "tls_version": raw_tls["tls_version"],
                "leaf_certificate": raw_tls["leaf_certificate"] or {},
                "certificate_chain": raw_tls["certificate_chain"],
                "chain_valid": raw_tls["chain_valid"],
                "chain_error": raw_tls["chain_error"],
            },
            # CT Collector 결과 - source: 내장 SCT(embedded_sct) 또는 crt.sh 폴백(crt.sh)
            # log_entries 0 = "crt.sh 조회 성공, CT에 없음", null = "미조회 또는 확인 못 함"
            "ct": {
                "first_seen": raw_ct["first_seen"],
                "source": raw_ct["source"],
                "sct_count": raw_ct["sct_count"],
                "log_entries": raw_ct["log_entries"],
            },
        },

        "signals": signals,

        # HTTP, TLS, CT 세 곳의 실패, 차단 기록 + Analyzer 실행 실패 기록을 합쳐 보존
        "errors": raw_http["errors"] + raw_tls["errors"] + raw_ct["errors"] + analyzer_errors,
    }
