# ---- HTTP Collector (collectors/http_collector.py) ----

MAX_REDIRECT_HOPS = 15         # 따라가는 최대 리다이렉트 횟수. 초과 hop은 관측만 하고 접속하지 않는다
HTTP_TIMEOUT_SECONDS = 10.0    # 연결, 읽기 타임아웃 (초)
MAX_BODY_BYTES = 5 * 1024 * 1024   # 바디 수집 상한 5MB. 초과분은 읽지 않고 truncated 표시
MAGIC_PROBE_BYTES = 2048       # magic 판독에 넘길 바디 앞부분 크기 - 파일 서명은 머리에 있어 이만큼이면 충분
MAGIC_SIGNATURE_BYTES = 8      # 사람/LLM 재확인용으로 보존할 원시 서명(hex) 길이

# User-Agent를 일반 브라우저 값으로 두는 이유: 악성 사이트는 봇(python-httpx/...)에게만
# 정상 페이지를 보여주는 클로킹을 한다. 봇 티가 나는 UA로는 관측 자체가 왜곡된다.
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

# ---- Certificate Collector (collectors/certificate_collector.py) ----

TLS_TIMEOUT_SECONDS = 10.0   # handshake 무응답 서버 대비

# ---- CT Collector (collectors/ct_collector.py) ----

CT_LOOKUP_URL = "https://crt.sh/"   # 폴백 조회처 (외부 서비스 - 교체 가능성 있음)
CT_TIMEOUT_SECONDS = 10.0    # crt.sh 무응답 대비 - 스캔 전체를 붙잡아 두지 않는다
CT_MAX_ATTEMPTS = 2          # 일시 오류(502 등) 대비 재시도 횟수

# ---- Analysis Record 저장 (storage.py) ----

# 결과 JSON을 저장할 기본 디렉터리 (상대경로 = 실행 위치 기준).
# Fargate 배포 시 컨테이너의 출력 마운트 경로로 교체될 값 - AWS팀 S3 연동 협의 대상.
RECORD_OUTPUT_DIR = "records"
