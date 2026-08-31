# ---- L2-H-04 url_shortener ----

# 알려진 URL 단축 서비스의 eTLD+1 명단.
# 단축 URL인가는 문자열 모양으로 알 수 없는 지식이라 known-list 방식으로 판단한다.
# 명단에 없는 신생 서비스는 놓치지만(미탐), 그 행동(다른 소유자로의 리다이렉트)은
# L2-H-01, 02가 관측하므로 시스템 차원에서는 잡힌다.
SHORTENER_DOMAINS = {
    "bit.ly", "t.co", "goo.gl", "tinyurl.com", "is.gd", "buff.ly",
    "ow.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy",
    "han.gl", "vo.la", "url.kr",          # 국내 서비스
}

# ---- L2-H-05 content_type_mismatch ----

# 실질적으로 같은 유형으로 취급할 쌍 - magic 판독 특성 보정.
# libmagic은 JSON을 text/plain으로, HTML을 간혹 text/xml로 읽는 등 선언 관행과
# 판독 결과가 어긋나는 정상 케이스가 있다. 운영 중 정상 사이트에서 오탐이 나오면
# 여기에 쌍을 추가한다 (유지보수 지점).
EQUIVALENT_PAIRS = {
    ("application/json", "text/plain"),   # magic은 JSON을 평문으로 읽는 경우가 많음
    ("text/html", "text/xml"),
    ("application/javascript", "text/plain"),
    ("text/css", "text/plain"),
}

# ---- L2-H-06 dangerous_file_download ----

# 위험 확장자 명단 — 이름 기반 탐지용 (H-04 명단과 같은 known-list 방식)
DANGEROUS_EXTENSIONS = {
    "exe", "msi", "dll", "scr", "com", "pif",          # Windows 실행 계열
    "bat", "cmd", "ps1", "vbs", "js", "jse", "wsf",    # 스크립트 계열
    "jar", "apk", "hta", "lnk", "iso",                 # 기타 실행 매개체
}

# magic 판독 결과 중 '실행파일'을 뜻하는 MIME — 실체 기반 탐지용
EXECUTABLE_MIMES = {
    "application/x-dosexec",          # Windows PE (exe/dll)
    "application/x-executable",       # Linux ELF
    "application/x-msdownload",
}

# ---- L2-C-01 certificate_age · L2-C-06 ct_first_seen ----

# 최근 발급/관측으로 볼 기준일 
# C-01(notBefore 기준)과 C-06(CT 관측 기준)이 같은 값을 공유한다 —
# 같은 최근 지식을 두 곳에서 따로 관리하지 않기 위함 (조정도 한곳에서).
FRESH_CERT_MAX_AGE_DAYS = 30
