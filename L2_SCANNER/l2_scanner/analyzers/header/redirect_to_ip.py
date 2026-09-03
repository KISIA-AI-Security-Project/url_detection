"""L2-H-03 IP 주소 리다이렉트 Analyzer

[목적] 리다이렉트 목적지가 일반 도메인이 아닌 직접 IP인지 확인한다.
       도메인 평판 검사(L1)를 우회하려고 IP로 직행시키는 패턴의 관측.

[입력]  Raw Data의 redirect_chain[]
[출력]  Signal evidence{destination_url, destination_ip} - 첫 번째 IP hop 기준

[범위 판단 - 계층 간 역할 분리]
원본 URL 자체가 IP인 경우는 접속 없이 문자열만으로 알 수 있으므로 L0의 담당이다.
L2는 접속했더니 IP로 보내더라라는 동적 관측만 담당한다.

[Collector의 SSRF 게이트와의 관계]
목적지가 내부망 IP(사설망·169.254.x 등)면 Collector가 접속 자체를 차단하지만,
hop 기록은 차단 전에 남기므로 이 Analyzer의 탐지는 영향받지 않는다.
공인 IP 목적지도 접속 실패(타임아웃 등)와 무관하게 탐지된다 -
실제 악성 IP는 봇 접속을 차단하는 경우가 많아 이 구조가 중요하다.

detected: true(IP hop 관측) / false(응답은 받았고 IP hop 없음) / null(여정 관측 불가)
네트워크 접속 없음 - L2-H-01의 Collector가 수집한 redirect_chain[]을 재사용한다.
"""

import ipaddress
from urllib.parse import urlsplit

SIGNAL = {"id": "L2-H-03", "scanner": "header", "name": "redirect_to_ip"}


def _host_ip(url: str):
    """URL의 호스트가 IP 주소이면 그 IP 문자열을, 도메인이면 None을 반환한다.

    urlsplit(...).hostname을 쓰는 이유: 포트(:8080)와 IPv6 대괄호([...])가
    자동으로 제거된 순수 호스트가 나와서 IP 판별이 어긋나지 않는다.
    """
    host = urlsplit(url).hostname
    if host is None:                # 호스트가 아예 없는 비정상 URL 대비
        return None
    try:
        ipaddress.ip_address(host)  # IPv4, IPv6 모두 처리. IP가 아니면 ValueError
        return host
    except ValueError:              # ValueError = 도메인이었다는 뜻
        return None


def analyze(raw: dict) -> dict:
    # chain의 각 목적지를 검사해 IP인 hop만 모은다
    ip_hops = []
    for hop in raw["redirect_chain"]:
        ip = _host_ip(hop["destination_url"])
        if ip is not None:
            ip_hops.append(
                {"destination_url": hop["destination_url"], "destination_ip": ip}
            )

    # hop도 최종 응답도 없으면 여정 자체를 관측 못 함 -> 판정 불가 (unknown != IP 없음)
    if not raw["redirect_chain"] and raw["final_url"] is None:
        detected = None
    else:
        detected = len(ip_hops) > 0

    # evidence에는 첫 번째 IP hop만 담는다 
    first = ip_hops[0] if ip_hops else {"destination_url": None, "destination_ip": None}

    return {
        **SIGNAL,
        "detected": detected,
        "evidence": {
            "destination_url": first["destination_url"],
            "destination_ip": first["destination_ip"],
        },
    }
