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
import magic

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
    for chunk in resp.iter_bytes():
        chunks.append(chunk)
        received += len(chunk)
        if received > MAX_BODY_BYTES:
            truncated = True
            break                          # 상한 도달 -> 더 읽지 않는다
    body = b"".join(chunks)[:MAX_BODY_BYTES]

    if not body:
        return   # 바디 없는 응답(204 등) -> response_body는 초기값(null들) 유지

    rb = result["response_body"]
    rb["truncated"] = truncated
    rb["detected_type"] = magic.from_buffer(body[:MAGIC_PROBE_BYTES], mime=True)
    result["download"]["magic_bytes"] = body[:MAGIC_SIGNATURE_BYTES].hex()

    if truncated:
        declared_len = resp.headers.get("content-length")
        rb["size"] = int(declared_len) if declared_len and declared_len.isdigit() else None
        rb["sha256"] = None
    else:
        rb["size"] = len(body)
        rb["sha256"] = hashlib.sha256(body).hexdigest()


def collect(url: str) -> dict:
    """URL 하나를 관측하고 Raw Data 딕셔너리를 반환한다.

    입력: 대상 URL 문자열
    출력: dict — original_url / current_url / final_url / status_code / redirect_chain[] / headers / response_body / download / errors[]

    [오류 처리]
    접속 실패, 차단, 비정상 응답도 예외를 던지지 않고 errors[]에 관측 결과로 남긴다.
    접속해봤는데 실패했다는 것 자체가 분석에 쓰이는 정보이기 때문이다.
    (예: 악성 IP는 봇 접속을 차단하는 경우가 많다 - 실패했어도 리다이렉트 관측은 유효)
    """

    # 모든 필드를 null로 미리 깔아둔다 - 수집 안 됨이 KeyError가 아니라
    # null(확인 안 됨)로 표현되도록. Analyzer들은 이 모양을 그대로 신뢰한다.
    result = {
        "original_url": url,
        "current_url": url,       # 여정 중 마지막으로 시도한 URL 
        "final_url": None,        # 3xx 아닌 최종 응답을 받은 URL. 못 받았으면 null
        "status_code": None,
        "redirect_chain": [],     # hop 기록 {source_url, destination_url, status_code, location}
        "headers": {              # 최종 응답에서 분석에 쓰는 헤더 3종
            "content_type": None,
            "content_disposition": None,
            "refresh": None,
        },
        "response_body": {
            "size": None,
            "detected_type": None,   # magic bytes 판독 결과 (서버가 조작 못 하는 실체 정보)
            "sha256": None,
            "truncated": False,      # 상한 초과로 바디가 잘렸는지 (증거 정직성 표시)
        },
        "download": {             # 파일 다운로드 관점의 메타 (L2-H-06/07의 재료)
            "filename": None,
            "extension": None,
            "mime_type": None,       # 서버가 선언한 유형 (파라미터 제거본)
            "magic_bytes": None,     # 바디 첫 8바이트 hex - 사람/LLM 재확인용 원시 서명
        },
        "errors": [],
    }

    current_url = url

    # TLS 검증은 일단 기본값(검증 O)으로 시작 - 자체 서명 인증서 사이트는 여기서
    # 접속 실패로 기록된다. 인증서 자체의 수집, 분석은 Certificate Collector(예정)와 역할 조정.
    with httpx.Client(
        timeout=HTTP_TIMEOUT_SECONDS,
        follow_redirects=False,               # 리다이렉트를 hop 단위로 직접 제어 (모듈 docstring 참고)
        headers={"User-Agent": USER_AGENT},
    ) as client:
        while True:
            result["current_url"] = current_url
            try:
                # stream으로 열면 헤더만 먼저 도착한다. 바디는 최종 응답에서만,
                # 그것도 상한까지만 읽는다 (3xx 응답의 바디는 읽지 않고 버림).
                with client.stream("GET", current_url) as resp:

                    # ---------- (A) 리다이렉트 응답: hop 기록 후 다음으로 ----------
                    if resp.status_code in REDIRECT_CODES:
                        location = resp.headers.get("location")  # httpx는 헤더 이름 대소문자 무관 조회

                        if location is None:
                            # 비정상: "다른 데로 가라"면서 목적지가 없음.
                            # 관측한 상태 코드는 남기고 여정 종료 (final_url은 null 유지. 최종 응답을 받은 게 아니기 때문)
                            result["status_code"] = resp.status_code
                            result["errors"].append(
                                {"url": current_url, "error": "3xx without Location"}
                            )
                            return result

                        # Location은 상대경로(/next)로 올 수 있다 -> 현재 URL 기준 절대화
                        next_url = urljoin(current_url, location)

                        # 접속 성공 여부와 무관하게 hop을 먼저 기록한다 
                        # 어디로 보내려 했는가는 그 자체로 관측 사실 (L2-H-03이 이 기록에 의존)
                        result["redirect_chain"].append({
                            "source_url": current_url,
                            "destination_url": next_url,
                            "status_code": resp.status_code,
                            "location": location,          # 헤더 원문 그대로 보존 (재검증용)
                        })

                        # 안전장치 1: 리다이렉트는 정확히 MAX_REDIRECT_HOPS회까지만 따라간다.
                        # 초과분 hop은 위에서 관측만 기록했고, 접속은 하지 않는다.
                        if len(result["redirect_chain"]) > MAX_REDIRECT_HOPS:
                            result["errors"].append(
                                {"url": next_url, "error": "max redirect hops exceeded"}
                            )
                            return result

                        # 안전장치 4: 내부망, 예약 주소로의 리다이렉트는 접속하지 않는다 (SSRF 방지)
                        blocked = _blocked_destination(next_url)
                        if blocked is not None:
                            result["errors"].append(
                                {"url": next_url,
                                 "error": f"redirect destination blocked ({blocked})"}
                            )
                            return result

                        current_url = next_url
                        continue   # 다음 hop으로

                    # ---------- (B) 3xx가 아닌 응답 = 여정의 끝. 최종 응답 기록 ----------
                    result["final_url"] = current_url
                    result["status_code"] = resp.status_code
                    result["headers"]["content_type"] = resp.headers.get("content-type")
                    result["headers"]["content_disposition"] = resp.headers.get("content-disposition")
                    result["headers"]["refresh"] = resp.headers.get("refresh")

                    # 바디 수집 (명세서 6장 response_body / download 트리)
                    _collect_body(resp, result)

                    # 파일 메타 1: 서버가 선언한 유형 (파라미터 제거 + 소문자)
                    result["download"]["mime_type"] = split_mime(
                        resp.headers.get("content-type")
                    )

                    # 파일 메타 2: 파일명 후보 - 두 단계로 찾는다
                    # 1순위: Content-Disposition의 filename / filename*= (RFC 5987 포함)
                    # 2순위: URL 경로의 마지막 조각 (직링크 다운로드 대비 fallback 헤더 없이 http://x/payload.ps1 로 배포하는 경우, 브라우저도 URL 경로명을 저장 파일명으로 쓴다)
                    cd = resp.headers.get("content-disposition")
                    filename = parse_content_disposition(cd)["filename"] if cd else None
                    if filename is None:
                        filename = filename_from_url(current_url)
                    result["download"]["filename"] = filename
                    result["download"]["extension"] = extension_from_filename(filename)

                    return result

            except httpx.RequestError as e:
                # 접속 실패(DNS 실패, 연결 거부, 타임아웃 등)도 지우지 말고 기록 
                # 확인 안 됨과 없음의 구분. 지금까지 쌓인 관측(redirect_chain 등)은 그대로 반환된다.
                result["errors"].append({"url": current_url, "error": str(e)})
                return result
