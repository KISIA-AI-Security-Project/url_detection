"""L2 HTTP Collector 

[역할]
대상 URL에 접속해 리다이렉트 여정을 한 hop씩 직접 따라가며 기록하고, 최종 응답의 헤더, 바디 정보를 수집해 Raw Data 딕셔너리로 반환한다.

[전체 overview]
Target URL -> [이 Collector: 접속 1회] -> Raw Data -> [Analyzer 8종: 계산만] -> Signals
네트워크 접속은 여기서 딱 한 번 일어난다. Analyzer들은 이 결과를 재사용만 한다.
(접속은 1회, 분석은 공유. 같은 URL에 기능마다 다시 접속하지 않는다)

[안전장치 4종] - 악성 서버는 스캐너를 공격 대상으로 삼을 수 있다는 전제
1. MAX_REDIRECT_HOPS : 무한 리다이렉트 루프(A->B->A->...)로 스캐너를 묶어두는 공격 방지
2. HTTP_TIMEOUT_SECONDS : 일부러 응답을 안 주는 서버에 붙잡히는 것 방지
3. MAX_BODY_BYTES : 초대형 응답을 흘려보내 메모리를 고갈시키는 공격 방지
4. SSRF 게이트 : 내부망, 클라우드 메타데이터 주소로 리다이렉트시켜 스캐너의 내부 권한을 훔치는 공격(SSRF) 방지
"""
import hashlib
import ipaddress
import socket
from urllib.parse import urljoin, urlsplit

import httpx

from l2_scanner.config.tuning import (
    MAX_REDIRECT_HOPS,
    HTTP_TIMEOUT_SECONDS,
    MAX_BODY_BYTES,
    MAGIC_PROBE_BYTES,
    MAGIC_SIGNATURE_BYTES,
    USER_AGENT,
)
from l2_scanner.utils.http_parsing import (
    parse_content_disposition,
    extension_from_filename,
    filename_from_url,
    split_mime,
)

# 다른 데로 가라는 상태 코드들 - HTTP 표준이 정한 프로토콜이라 조정값이 아니므로 config가 아닌 여기 둔다. 3xx 전부가 아님에 주의 
# 304(Not Modified)는 캐시 응답이지 리다이렉트가 아니므로 제외한다.
REDIRECT_CODES = {301, 302, 303, 307, 308}


def _blocked_destination(url: str) -> str | None:
    """리다이렉트 목적지가 내부망, 예약 주소이면 차단 사유 문자열을, 정상이면 None을 반환한다.

    [무엇을 막는가 - SSRF]
    악성 서버가 "http://169.254.169.254/latest/meta-data/" (AWS 자격증명 조회 주소)나
    "http://192.168.0.1/admin" 같은 내부 주소로 리다이렉트시키면, 스캐너가 자기 위치에서
    그 내부 자원에 대신 접속해주는 꼴이 된다(SSRF, Server-Side Request Forgery).
    운영 환경(AWS)에서는 자격증명 유출로 직결되므로 목적지를 접속 전에 검사한다.

    [판정 기준]
    ipaddress의 is_global 속성 하나로 판정한다 - 사설망(10/8, 192.168/16 등),
    루프백(127.x), 링크로컬(169.254.x = AWS 메타데이터 포함), 예약 대역이
    전부 is_global=False라서 개별 대역을 나열할 필요가 없다.

    [설계 결정 2가지]
    - 차단은 악성 판정이 아니라 정책 차단이다. 차단 사실과 사유를 errors[]에 기록할 뿐, detected 판단은 Analyzer(L2-H-03 등)의 몫이다.
    - 원본 URL 자체가 IP, 내부망인 경우는 여기서 다루지 않는다. 그것은 접속 전 문자열로 알 수 있는 정보라 L0/Reachability 게이트의 담당이다.
    """
    host = urlsplit(url).hostname
    if host is None:
        return None   # 호스트조차 없는 비정상 URL -> 차단 아닌 접속 단계 자연 실패에 맡긴다

    # 1) 호스트가 IP 리터럴이면 DNS 없이 바로 판정
    try:
        ip = ipaddress.ip_address(host)
        return None if ip.is_global else f"non-global address {ip}"
    except ValueError:
        pass   # ValueError = IP가 아니라 도메인이라는 뜻 -> 아래에서 DNS로 판정

    # 2) 도메인이면 해석된 모든 IP를 확인한다 (A 레코드가 여러 개일 수 있고,그 중 하나라도 내부망이면 차단). 
    # 해석 실패는 차단하지 않는다. 어차피 접속 단계에서 실패하고 그 오류가 기록된다.
    # 한계: 해석 시점과 실제 연결 시점 사이에 IP를 바꾸는 DNS Rebinding까지는 여기서 못 막는다.
    # 격리 실행 환경(컨테이너)이 마지막 방어선이라는 전제.
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return None
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])   # getaddrinfo 결과의 (주소, ...) 튜플에서 주소만
        if not ip.is_global:
            return f"{host} resolves to non-global address {ip}"
    return None


def _collect_body(resp, result: dict) -> None:
    """최종 응답 바디를 상한(MAX_BODY_BYTES)까지 스트리밍으로 읽어 result에 기록한다.

    [왜 스트리밍인가]
    resp.content는 바디 전체를 한 번에 메모리에 올린다. 악성 서버가 수 GB를 흘려보내면 스캐너가 죽는다. 
    그래서 조각(chunk) 단위로 받다가 상한을 넘으면 그 시점에 읽기를 중단한다.

    [잘렸을 때의 기록 원칙 - 확인 안 됨과 없음의 구분]
    - sha256: 부분 바디의 해시는 그 파일의 해시가 아니다. VirusTotal 조회 등에 쓰면 거짓 정보가 되므로 null(확인 못 함)로 남긴다.
    - size: 실제 크기를 끝까지 안 읽었으므로 모른다. 서버가 선언한 Content-Length가 있을 때만 그 값을 기록하고, 없으면 null.
    - detected_type / magic_bytes: 파일 서명은 첫 바이트들에 있으므로 잘려도 유효하다.
    - truncated=True 표시로 이 기록은 부분 관측임을 후속 단계에 알린다.
    """
    chunks = []
    received = 0
    truncated = False
    try:
        for chunk in resp.iter_bytes():
            remaining = MAX_BODY_BYTES - received
            chunks.append(chunk[:max(remaining, 0)])
            received += min(len(chunk), max(remaining, 0))
            if len(chunk) > remaining:
                truncated = True
                break
    except httpx.HTTPError as exc:
        truncated = True
        result["errors"].append({"stage": "http_body", "code": "response_body_interrupted", "error": str(exc), "received_bytes": received})
    body = b"".join(chunks)[:MAX_BODY_BYTES]

    result["response_body"].update({"truncated": truncated, "received_bytes": len(body), "body_complete": not truncated})
    if not body:
        return   # 바디 없는 응답(204 등) -> response_body는 초기값(null들) 유지

    rb = result["response_body"]
    rb["truncated"] = truncated
    try:
        import magic
        rb["detected_type"] = magic.from_buffer(body[:MAGIC_PROBE_BYTES], mime=True)
    except Exception as exc:
        result["errors"].append({"stage":"body_type", "code":"mime_detection_failed", "error":str(exc)})
    result["download"]["magic_bytes"] = body[:MAGIC_SIGNATURE_BYTES].hex()

    if truncated:
        declared_len = resp.headers.get("content-length")
        rb["size"] = int(declared_len) if declared_len and declared_len.isdigit() else None
        rb["sha256"] = None
    else:
        rb["size"] = len(body)
        rb["sha256"] = hashlib.sha256(body).hexdigest()


def collect(url: str, *, resolver=None, transport=None) -> dict:
    """공통 수집기의 공개 주소 검증·IP 고정·쿠키·부분 응답 보존을 사용한다."""
    from url_collector import CollectionPolicy, collect_url, system_resolver
    from l2_scanner.adapters.page_snapshot import to_l2_http_raw
    snapshot = collect_url(url, CollectionPolicy(request_timeout_seconds=HTTP_TIMEOUT_SECONDS,
        max_redirects=MAX_REDIRECT_HOPS, max_body_bytes=MAX_BODY_BYTES, user_agent=USER_AGENT),
        resolver=resolver or system_resolver, transport=transport)
    return to_l2_http_raw(snapshot)
