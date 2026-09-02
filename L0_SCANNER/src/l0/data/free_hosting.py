"""
그룹 A-3(기본 CDN/무료 호스팅) 판정에 쓰는 목록.

이들 서비스는
(1) 가입만 하면 누구나 즉시 서브도메인을 발급받고
(2) TLS 인증서가 자동 발급되며
(3) 도메인 등록 비용·심사가 없다는 공통점이 있다.
피싱 페이지를 짧은 주기로 반복 재배포하기에 최적이라 실제 캠페인에서 광범위하게 악용된다.

주의: 이 목록에 걸린다고 그 자체로 악성은 아니다. 정상 개발자·기업도 대량으로 쓴다.
어디까지나 다른 신호와 함께 볼 약한 지표로 취급한다.

[출처]
- Mozilla Public Suffix List — PRIVATE DOMAINS 섹션
  (서비스 제공자가 "이 아래는 제3자가 등록하는 영역"이라고 직접 등록한 목록)
- MITRE ATT&CK: T1584.004(Compromise Infrastructure: Server),
  T1572(Protocol Tunneling), T1567(Exfiltration Over Web Service)
- APWG Phishing Activity Trends Report
- CISA/FBI Joint Cybersecurity Advisory

[갱신 주기] 반기 1회. 신규 서버리스/터널링 서비스가 계속 등장하므로 주기적 확인 필요.
"""

# 목록 버전 — analysis_record의 list_version에 실려 저장된다.
# 형식: "<목록명>-<갱신 연월>"
FREE_HOSTING_VERSION = "free_hosting-2026-08"

# 제공자 도메인 -> 카테고리.
#
# set이 아니라 dict인 이유는 analysis_record의 category 필드를 채우기 위함이다.
# 네 분류는 "주소 발급이 제품에서 차지하는 위치"로 나뉜다.
#   SERVERLESS / HOSTING — 주소는 제품을 쓰기 위한 수단이다. 배포 파이프라인은
#     주소 없이 완성되지 않으므로 무료로 즉시 발급할 수밖에 없다.
#   DDNS / TUNNEL — 주소 자체가 판매 상품이다. 변동 IP를 가리키는 고정된 이름,
#     로컬 서버를 외부에 노출시키는 접점이 곧 서비스의 전부다.
#
# 위협 성격도 갈린다. 수단형은 피싱 페이지 배포에, 상품형은 C2 채널과
# 데이터 반출에 주로 쓰이므로 종합 단계에서 다른 시나리오로 해석해야 한다.
FREE_HOSTING_PROVIDERS: dict[str, str] = {
    # --- 서버리스 / 엣지 ---
    #     코드를 배포하면 <프로젝트명>.<플랫폼도메인>이 즉시 발급되고 TLS도 자동으로 붙는다.
    #     차단당해도 즉시 재배포할 수 있고, 엣지 네트워크라 전 세계에서 빠르게 뜬다.
    "workers.dev": "SERVERLESS",
    "pages.dev": "SERVERLESS",
    "vercel.app": "SERVERLESS",
    "netlify.app": "SERVERLESS",
    "deno.dev": "SERVERLESS",
    # --- 정적 호스팅 / PaaS ---
    #     파일만 올리면 그대로 내보내주거나, 코드만 올리면 서버 준비까지 대신해준다.
    "github.io": "HOSTING",
    "gitlab.io": "HOSTING",
    "firebaseapp.com": "HOSTING",
    "web.app": "HOSTING",
    "surge.sh": "HOSTING",
    "glitch.me": "HOSTING",
    "herokuapp.com": "HOSTING",
    # --- 동적 DNS ---
    #     변동 IP를 가리키는 고정된 이름을 유지해준다. 악성코드에 C2 주소를 박아넣을 때
    #     IP를 박으면 그 IP만 차단하면 되고 도메인을 사면 결제 흔적이 남지만,
    #     DDNS 이름은 무료·익명이면서 서버를 옮겨도 그대로 쓸 수 있다.
    #
    #     주의: 회사 도메인(no-ip.com)이 아니라 무료 호스트명이 발급되는 도메인을 넣는다.
    #     no-ip.com은 No-IP 자사 홈페이지라 www.no-ip.com이 오탐된다.
    "duckdns.org": "DDNS",
    "ddns.net": "DDNS",
    "zapto.org": "DDNS",
    "dynu.net": "DDNS",
    # No-IP 무료 계열
    "no-ip.org": "DDNS",
    "no-ip.biz": "DDNS",
    "no-ip.info": "DDNS",
    "hopto.org": "DDNS",
    "sytes.net": "DDNS",
    "myftp.org": "DDNS",
    # --- 터널링 ---
    #     안에서 밖으로 먼저 연결을 열고 그 통로로 외부 요청을 되돌려 보낸다.
    #     방화벽은 나가는 연결을 막지 않으므로(막으면 웹서핑조차 안 된다),
    #     침투한 장비에서 실행하면 데이터 반출과 원격 제어 경로가 동시에 생긴다.
    "ngrok.io": "TUNNEL",
    "ngrok-free.app": "TUNNEL",
    "trycloudflare.com": "TUNNEL",
    "loca.lt": "TUNNEL",  # localtunnel 현행 도메인 (구 localtunnel.me는 사실상 미사용)
}
