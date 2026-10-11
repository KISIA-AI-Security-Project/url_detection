"""L2 Scanner 진입점

[처리 흐름]
    scan(url)
      1. HTTP Collector가 접속 1회로 HTTP Raw Data 수집  (collectors/http_collector.py)
      2. Certificate Collector가 TLS handshake 1회로 인증서 수집 (collectors/certificate_collector.py) - 대상 호스트는 HTTPS URL(최종 도착 우선, 없으면 원본)에서 결정
      3. CT Collector가 CT 최초 관측 시각 수집 (collectors/ct_collector.py) - 내장 SCT 우선(접속 없음), SCT 없는 인증서만 crt.sh 폴백 조회
      4. Header Analyzer 9종 + Certificate Analyzer 8종이 Raw Data를 공유해 Signal 생성 (Analyzer는 네트워크 재접속 없음. C-06만 CT Raw Data를 읽는다)
      5. JSON(dict)으로 조립해 반환

"""
from datetime import datetime
from urllib.parse import urlsplit

from l2_scanner.collectors.http_collector import collect
from l2_scanner.collectors.certificate_collector import collect as collect_certificate, TLS_DEFAULT_PORT
from l2_scanner.collectors.ct_collector import collect as collect_ct
from l2_scanner.analyzers.header import (
    redirect_chain,
    redirect_domain_change,
    redirect_to_ip,
    url_shortener,
    http_refresh,
    forced_download,
    content_type_mismatch,
    dangerous_file_download,
    protocol_downgrade,
)
from l2_scanner.analyzers.certificate import (
    certificate_age,
    certificate_validity,
    hostname_match,
    self_signed,
    certificate_chain,
    ct_first_seen,
    tls_version,
    wildcard_certificate,
)
from l2_scanner.utils.http_parsing import etld1

TECHNICAL_PREDICATES={
    'L2-H-01':'At least one recorded HTTP redirect hop',
    'L2-H-02':'Recorded redirect URLs have differing registered domains',
    'L2-H-03':'A recorded redirect target is an IP literal',
    'L2-H-04':'A recorded journey URL matches the configured shortener-domain reference',
    'L2-H-05':'Declared HTTP type differs from prefix libmagic classification after configured aliases',
    'L2-H-06':'Filename extension or prefix MIME classification matches configured executable-type lists',
    'L2-H-07':'Content-Disposition declares attachment',
    'L2-H-08':'HTTP response contains a Refresh header',
    'L2-H-09':'A recorded redirect moves from HTTPS to HTTP',
    'L2-C-02':'Certificate validity interval excludes observation time',
    'L2-C-03':'Certificate hostname comparison returned matched=false',
    'L2-C-04':'Leaf certificate self-signature verification returned true',
    'L2-C-05':'Certificate chain verification returned valid=false',
    'L2-C-07':'Negotiated TLS version is in configured legacy-version set',
    'L2-C-08':'Certificate contains a wildcard name',
}


def _technical_result(signal):
    if signal.get('result_kind') == 'measurement':
        signal['technical_scope'] = {
            'measurement': ('Whole elapsed days from collected CT timestamp to measured_at' if signal['id']=='L2-C-06'
                            else 'Whole elapsed days from certificate notBefore to measured_at'),
            'certainty': 'technical_observation_only', 'url_verdict': 'not_assessed',
            'limits': ('Collected CT timestamp and its source; no freshness threshold or URL verdict.' if signal['id']=='L2-C-06'
                       else 'notBefore is the certificate validity start, not its issuance event or domain creation time. No freshness threshold is applied.'),
        }
        return signal
    signal['technical_scope']={'predicate':TECHNICAL_PREDICATES.get(signal['id']),
        'certainty':'technical_observation_only','url_verdict':'not_assessed',
        'limits':'Prefix file-type inference is not full-file identity or execution. TLS/HTTP properties do not establish content safety, ownership or intent.'}
    return signal

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
    protocol_downgrade,       # L2-H-09 (명세서 5장 추가 구현)
]

# C-06(ct_first_seen)은 이 목록에 없다 - TLS가 아닌 CT Raw Data를 읽으므로 scan()에서 따로 호출
CERTIFICATE_ANALYZERS = [
    certificate_age,          # L2-C-01
    certificate_validity,     # L2-C-02
    hostname_match,           # L2-C-03
    self_signed,              # L2-C-04
    certificate_chain,        # L2-C-05
]

# 명세서 5장 추가 구현분 (TLS Raw를 읽는다). C-06 뒤 번호라 별도 목록으로 두고
# scan()에서 C-06 다음에 실행한다 - signals[]가 기능 번호 순서를 유지하도록
CERTIFICATE_ANALYZERS_EXTENDED = [
    tls_version,              # L2-C-07
    wildcard_certificate,     # L2-C-08
]


def _now_iso() -> str:
    # 로컬 타임존이 붙은 ISO 8601 시각 (예시: 2026-08-24T09:20:10+09:00)
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _run_analyzer(analyzer, raw: dict, errors: list) -> dict:
    """Analyzer 1개를 격리 실행한다 - 하나가 죽어도 전체 스캔은 계속된다. 

    Analyzer가 예상 못 한 Raw Data로 예외를 내면, 이미 수집한 관측과 나머지 Signal까지 전부 잃는 것이 기존 동작이었다. 
    검증 실패해도 관측은 보존에 따라 실패한 기능만 detected null(검사 불가) Signal로 대체하고 사유를 errors[]에 남긴다.
    각 Analyzer 모듈의 SIGNAL 상수(id/scanner/name)가 대체 Signal의 뼈대가 된다.
    """
    try:
        return _technical_result(analyzer.analyze(raw))
    except Exception as e:
        errors.append({
            "code": "analyzer_failed", "stage":"analysis",
            "impact_scope":"analysis",
            "analyzer": analyzer.SIGNAL["id"],
            "occurrence_id": 'l2:analysis:'+analyzer.SIGNAL['id'],
            "target": {k:raw[k] for k in ('original_url','final_url','hostname') if raw.get(k) is not None},
            "error": f"{type(e).__name__}: {e}",
        })
        failed = {**analyzer.SIGNAL, "evidence": {}, "error": errors[-1]}
        if analyzer.SIGNAL.get('result_kind') == 'measurement':
            failed['measurement_state'] = 'unavailable'
        else:
            failed['detected'] = None
        return _technical_result(failed)


def _tls_target(raw_http: dict) -> tuple[str | None, int]:
    """인증서를 관측할 (호스트, 포트)를 정한다.

    우선순위: 1. 최종 도착 URL이 https면 그 호스트 - 사용자가 실제로 도달하는 지점의인증서가 분석 대상. 
             2. 최종 응답을 못 받았으면 원본 URL이 https일 때 그 호스트.
    둘 다 https가 아니면 (None, 기본 포트) - 인증서 관측 불가(unknown)로 처리된다.
    """
    for candidate in (raw_http["final_url"], raw_http.get("current_url"), raw_http["original_url"]):
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
    """기존 독립 경로를 유지하고 수집 결과 분석을 공통 함수로 보낸다."""
    return _scan_collected(collect(url), _now_iso())

def scan_snapshot(snapshot) -> dict:
    """같은 HTTP 스냅샷의 헤더·본문·한계를 분석한다. HTTP 재접속은 없다."""
    from l2_scanner.adapters.page_snapshot import to_l2_http_raw
    raw_http = to_l2_http_raw(snapshot)
    raw_http["snapshot_id"] = snapshot.snapshot_id
    raw_http["http_policy_blocked"] = any(e.code == "target_policy_blocked" for e in snapshot.collection_errors)
    result = _scan_collected(raw_http, _now_iso())
    result["scan"]["snapshot_id"] = snapshot.snapshot_id
    return result

def _scan_collected(raw_http, started_at):
    # 2. TLS 인증서 수집 (handshake 1회) - HTTPS 대상이 없으면 unknown 구조로 남는다
    tls_host, tls_port = _tls_target(raw_http)
    if raw_http.get("http_policy_blocked"):
        tls_host = None
    raw_tls = collect_certificate(tls_host, tls_port)

    # 3. CT 최초 관측 수집 - 내장 SCT 우선(접속 없음), 없으면 crt.sh 폴백 조회
    leaf = raw_tls["leaf_certificate"]
    try:
        raw_ct = collect_ct(leaf["fingerprint"] if leaf else None, leaf["sct_timestamps"] if leaf else None)
    except Exception as exc:
        raw_ct = {"first_seen":None, "source":None, "sct_count":None, "log_entries":None,
                  "errors":[{"stage":"ct", "code":"ct_collection_failed", "error":str(exc)}]}

    for stage,collected,target in [('http',raw_http,{'url':raw_http.get('current_url') or raw_http.get('original_url')}),
                                   ('tls',raw_tls,{'hostname':raw_tls.get('hostname')}),('ct',raw_ct,{'hostname':raw_tls.get('hostname')})]:
        for index,error in enumerate(collected.get('errors',[])):
            error.setdefault('stage',stage)
            error.setdefault('occurrence_id',f'l2:{stage}:{index}')
            error.setdefault('impact_scope','acquisition')
            for key,value in target.items():error.setdefault(key,value)

    # 4. 분석 - Analyzer는 네트워크 접속 없이 Raw Data만 읽는다.
    # 각 Analyzer는 격리 실행된다 - 하나가 예외로 죽어도 나머지 Signal과 관측은 보존
    analyzer_errors: list = []
    signals = [_run_analyzer(a, raw_http, analyzer_errors) for a in HEADER_ANALYZERS]
    signals += [_run_analyzer(a, raw_tls, analyzer_errors) for a in CERTIFICATE_ANALYZERS]
    signals += [_run_analyzer(ct_first_seen, raw_ct, analyzer_errors)]   # C-06만 CT Raw Data를 읽는다
    signals += [_run_analyzer(a, raw_tls, analyzer_errors) for a in CERTIFICATE_ANALYZERS_EXTENDED]

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
            "status": ("failed" if raw_http["status_code"] is None else "partial"
                       if raw_http["errors"] or raw_http["response_body"].get("truncated") or analyzer_errors else "completed"),
            "observation": {"http_response_received":raw_http["status_code"] is not None,
                            "body_complete":raw_http["response_body"].get("body_complete"),
                            "tls_observed":bool(raw_tls["leaf_certificate"]),
                            "tls_scope":"separate TLS connection to the recorded hostname", "finished":True},
            "started_at": started_at,
            "finished_at": finished_at,
        },

        "raw": {
            "http": {
                "original_url": raw_http["original_url"],
                "current_url": raw_http.get("current_url"),
                "response_received": raw_http.get("response_received"),
                "redirect_journey_complete": raw_http.get("redirect_journey_complete"),
                "errors": [{"stage":"http",**e} for e in raw_http['errors']],
                "snapshot_id":raw_http.get('snapshot_id'),
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
                "errors": [{"stage":"tls",**e} for e in raw_tls['errors']],
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
                "errors": [{"stage":"ct",**e} for e in raw_ct['errors']],
                "first_seen": raw_ct["first_seen"],
                "source": raw_ct["source"],
                "sct_count": raw_ct["sct_count"],
                "log_entries": raw_ct["log_entries"],
            },
        },

        "signals": signals,

        # HTTP, TLS, CT 세 곳의 실패, 차단 기록 + Analyzer 실행 실패 기록을 합쳐 보존
        "errors": ([{"stage":"http",**e} for e in raw_http['errors']] + [{"stage":"tls",**e} for e in raw_tls['errors']]
                   + [{"stage":"ct",**e} for e in raw_ct['errors']] + analyzer_errors),
    }
