"""L2-C-03 도메인-인증서 일치 Analyzer

[목적] 접속한 호스트명과 인증서의 발급 대상(SAN)이 일치하는지 확인한다.
       불일치 = "이 도메인을 위해 발급된 인증서가 아니다" — 도용, 설정 오류의 관측.

[입력]  TLS Raw Data의 hostname, leaf_certificate.san (없으면 subject의 CN을 참고)
[출력]  Signal evidence{matched, hostname, matched_name}

[대조 기준 — 브라우저와 동일]
- 현대 브라우저는 SAN만 본다. SAN 확장이 아예 없는 구식 인증서만 subject CN으로 보완.
- 와일드카드 규칙: "*.example.com"은 왼쪽 라벨 한 칸만 대체한다.
    a.example.com   <- 일치
    a.b.example.com <- 불일치 (두 칸)
    example.com     <- 불일치 (0칸)

[Collector와의 역할 분리]
Collector는 handshake에서 check_hostname을 꺼고 접속한다 - 호스트명 검사를 여기서
독립적으로 수행해, 체인 신뢰성(C-05)과 호스트명 일치(C-03)를 별개 Signal로 관측하기 위함.

네트워크 접속 없음 - Certificate Collector가 수집, 파싱한 값을 재사용한다.
"""

import re

SIGNAL = {"id": "L2-C-03", "scanner": "certificate", "name": "hostname_certificate_match"}   


def _name_matches(hostname: str, pattern: str) -> bool:
    """인증서의 이름 패턴 하나가 호스트명과 일치하는지 판정한다 (대소문자 무시)."""
    hostname = hostname.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")

    if not pattern.startswith("*."):
        return hostname == pattern

    # 와일드카드: *.example.com → 왼쪽 라벨 정확히 한 칸만 대체
    suffix = pattern[2:]                      # "example.com"
    if not hostname.endswith("." + suffix):
        return False
    left = hostname[: -(len(suffix) + 1)]     # 접미사 앞부분 = 대체된 라벨
    return bool(left) and "." not in left     # 비어 있지 않고, 라벨 한 칸일 것


def _cn_from_subject(subject: str) -> str | None:
    """RFC 4514 subject 문자열에서 CN 값만 뽑는다 (SAN 없는 구식 인증서 보완용)."""
    match = re.search(r"(?:^|,)CN=([^,]+)", subject)
    return match.group(1) if match else None


def analyze(tls: dict) -> dict:
    hostname = tls["hostname"]
    leaf = tls["leaf_certificate"]

    matched = None        # null = 대조 자체를 못 함 (인증서 없음)
    matched_name = None

    if leaf and hostname:
        # 대조 후보: SAN 전체. SAN 확장이 없으면 subject CN으로 보완
        candidates = list(leaf["san"])
        if not candidates:
            cn = _cn_from_subject(leaf["subject"])
            if cn:
                candidates = [cn]

        matched = False
        for name in candidates:
            if _name_matches(hostname, name):
                matched = True
                matched_name = name      # 어떤 이름에 일치했는지 근거로 보존
                break

    return {
        **SIGNAL,
        # 불일치가 관측됨(matched false)이 신호. 대조 자체를 못 했으면(matched null)
        # 판정 불가 -> null - unknown != 불일치 
        "detected": None if matched is None else matched is False,
        "evidence": {
            "matched": matched,
            "hostname": hostname,
            "matched_name": matched_name,
        },
    }
