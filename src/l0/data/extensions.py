"""
그룹 C-1(파일 다운로드)·C-2(이중 확장자)가 공유하는 확장자 표.

목록을 둘로 나누지 않는다. MIME 화이트리스트와 확장자 블랙리스트를 따로 관리하면
새 확장자가 나올 때 여러 곳을 고쳐야 하고 갱신 누락이 생긴다.

[구조] 확장자 -> (web_safe, role). 두 축이 서로 독립이다.
    web_safe — C-1의 판정 기준. False면 다운로드 유도로 본다.
    role     — C-2의 판정 기준. DECEPTIVE(앞자리 위장) / DANGEROUS(뒷자리 실제).

초안에 있던 category(EXECUTABLE/SCRIPT/DOCUMENT 등)는 넣지 않는다. 판정에
쓰이지 않고, 레코드의 extension 값이 이미 종류를 말해 주므로 중복이다.
무엇보다 "EXECUTABLE이 DOCUMENT보다 위험하다"는 서열에 근거 있는 공식이
없어, 새 확장자를 넣을 때마다 근거 없는 분류를 하나씩 더 정해야 했다.

js가 web_safe=True이면서 role="DANGEROUS"인 것이 이 표의 핵심이다.
/app.js는 정상 웹 리소스지만 logo.png.js는 이중 확장자다. 두 축이 독립이라
한 표에 담긴다.

[선정 기준]
  포함 (둘 중 하나)
    1. 코퍼스 경로에서 관측되었고 웹이 렌더링하는 확장자 -> web_safe=True
       오탐을 막는 것이 목적이다. php·html이 경로 확장자의 94%를 차지한다.
    2. 실제 악성 배포에 쓰이는 확장자 -> 탐지 대상
       코퍼스 관측치 + MITRE ATT&CK T1204(User Execution),
       T1566.001(Spearphishing Attachment)에 언급되는 포맷.
       국내 사칭용 문서 포맷(hwp 계열)은 코퍼스 관측 0건이나 국내 대상
       서비스이므로 문헌 근거로 포함한다.
  제외
    위 둘 중 어디에도 해당하지 않으면 넣지 않는다. 목록 밖은 해당없음으로
    두되 경로에서 나온 것은 value에 기록해 목록 보강 근거로 삼는다.

[근거] 악성 URL 1,007,881건 분석. 경로에서 확장자 321,099건 / 고유 120종 관측.
주석의 건수는 그 관측치다.

[갱신 주기] 분기 1회. 신규 배포 포맷과 목록 밖으로 기록된 확장자를 함께 검토한다.
"""

from __future__ import annotations

# 목록 버전 — analysis_record의 list_version에 실려 저장된다.
EXTENSION_RISK_VERSION = "extension_risk-2026-08"

EXTENSION_RISK_MAP: dict[str, tuple[bool, str | None]] = {
    # ------------------------------------------------------------------
    # 웹 리소스 — 브라우저가 렌더링한다. 경로 확장자의 94.36%가 여기다.
    # 이들을 SAFE로 두지 않으면 정상 사이트가 대량 오탐된다.
    # ------------------------------------------------------------------
    "php": (True, None),    # 165,441건 — 전체의 51.5%
    "html": (True, None),   # 124,207건
    "htm": (True, None),    #  11,022건
    "aspx": (True, None),   #     630건
    "asp": (True, None),    #     602건
    "jsp": (True, None),    #     313건
    "shtml": (True, None),  #     123건
    "phtml": (True, None),
    "do": (True, None),
    "cgi": (True, None),
    "css": (True, None),
    "json": (True, None),
    "xml": (True, None),
    # 500건. 웹에선 정상이지만 이중 확장자 뒷자리에 오면 위험하다.
    "js": (True, "DANGEROUS"),
    # ------------------------------------------------------------------
    # 미디어 — 브라우저가 표시·재생한다. 이중 확장자 앞자리로 흔히 쓰인다.
    # ------------------------------------------------------------------
    "txt": (True, "DECEPTIVE"),   # 1,278건
    "png": (True, "DECEPTIVE"),   #   312건
    "jpg": (True, "DECEPTIVE"),   #   179건
    "ico": (True, "DECEPTIVE"),   #   113건
    "jpeg": (True, "DECEPTIVE"),
    "gif": (True, "DECEPTIVE"),
    "webp": (True, "DECEPTIVE"),
    "bmp": (True, "DECEPTIVE"),
    "svg": (True, "DECEPTIVE"),
    "csv": (True, "DECEPTIVE"),
    "mp3": (True, "DECEPTIVE"),
    "mp4": (True, "DECEPTIVE"),
    "wav": (True, "DECEPTIVE"),
    "avi": (True, "DECEPTIVE"),
    "mkv": (True, "DECEPTIVE"),
    "mov": (True, "DECEPTIVE"),
    "wmv": (True, "DECEPTIVE"),
    # ------------------------------------------------------------------
    # 문서 — 다운로드되지만 업무상 흔하다.
    # ------------------------------------------------------------------
    "pdf": (False, "DECEPTIVE"),   # 118건
    "doc": (False, "DECEPTIVE"),
    "docx": (False, "DECEPTIVE"),
    "xls": (False, "DECEPTIVE"),
    "xlsx": (False, "DECEPTIVE"),
    "ppt": (False, "DECEPTIVE"),
    "pptx": (False, "DECEPTIVE"),
    "rtf": (False, "DECEPTIVE"),
    # 국내 대상. 코퍼스(해외 피싱 피드) 관측 0건이나 문헌 근거로 포함한다.
    "hwp": (False, "DECEPTIVE"),
    "hwpx": (False, "DECEPTIVE"),
    "hwt": (False, "DECEPTIVE"),
    "show": (False, "DECEPTIVE"),
    "cell": (False, "DECEPTIVE"),
    # ------------------------------------------------------------------
    # 압축 — 내용물을 감춘다.
    # ------------------------------------------------------------------
    "zip": (False, "DECEPTIVE"),    # 698건
    "rar": (False, "DECEPTIVE"),
    "7z": (False, "DECEPTIVE"),
    "tar": (False, "DECEPTIVE"),
    "gz": (False, "DECEPTIVE"),
    # ------------------------------------------------------------------
    # 디스크 이미지 — 마운트하면 그 안에서 실행된다. 코퍼스 관측 0건.
    # ------------------------------------------------------------------
    "iso": (False, "DANGEROUS"),
    "img": (False, "DANGEROUS"),
    "vhd": (False, "DANGEROUS"),
    "dmg": (False, "DANGEROUS"),
    # ------------------------------------------------------------------
    # 실행 바이너리
    #
    # com(DOS 실행 파일)은 넣지 않는다. 경로에서 2,271건 관측되었으나 전부
    # pg_www.wellsfargo.com 같은 도메인 문자열이었다. 쿼리까지 합치면 8,500건이
    # 넘는다. 실제 DOS COM 파일은 현재 위협에서 사라졌고 충돌 비용만 크다.
    # 같은 이유로 c·io·nl·fr·jp·uk·de도 넣지 않는다.
    # ------------------------------------------------------------------
    "exe": (False, "DANGEROUS"),   # 784건
    "msi": (False, "DANGEROUS"),
    "scr": (False, "DANGEROUS"),
    "cpl": (False, "DANGEROUS"),
    "pif": (False, "DANGEROUS"),
    "dll": (False, "DANGEROUS"),
    "sys": (False, "DANGEROUS"),
    "apk": (False, "DANGEROUS"),
    "dex": (False, "DANGEROUS"),
    "pkg": (False, "DANGEROUS"),
    # ------------------------------------------------------------------
    # IoT 봇넷 바이너리 — 아키텍처명을 확장자처럼 쓴다.
    # Mirai 계열 드로퍼가 /bins/mirai.x86, kaizen.arm7 형태로 아키텍처별
    # 바이너리를 뿌린다. 합계 약 1,329건으로 exe(784건)보다 많이 관측되었다.
    # ------------------------------------------------------------------
    "mips": (False, "DANGEROUS"),  # 173건
    "sh4": (False, "DANGEROUS"),   # 141건
    "arm7": (False, "DANGEROUS"),  # 140건
    "m68k": (False, "DANGEROUS"),  # 135건
    "x86": (False, "DANGEROUS"),   # 123건
    "ppc": (False, "DANGEROUS"),   # 115건
    "arm5": (False, "DANGEROUS"),  # 109건
    "arm6": (False, "DANGEROUS"),  # 107건
    "mpsl": (False, "DANGEROUS"),  # 107건
    "arm": (False, "DANGEROUS"),   # 106건
    "arc": (False, "DANGEROUS"),   #  90건
    "i686": (False, "DANGEROUS"),  #  89건
    "i586": (False, "DANGEROUS"),
    "spc": (False, "DANGEROUS"),
    # ------------------------------------------------------------------
    # 스크립트·간접 실행
    #
    # sh는 ccTLD(.sh, 세인트헬레나)와 겹친다. 코퍼스 3,748건은 전부 bin.sh·w.sh
    # 형태의 실제 스크립트였으나, 경로 끝의 도메인 문자열이 오탐될 여지가 있다.
    # 정상 코퍼스 확보 시 재확인할 것.
    # ------------------------------------------------------------------
    "sh": (False, "DANGEROUS"),        # 3,748건 — 최다 위험 확장자
    "bash": (False, "DANGEROUS"),
    "ps1": (False, "DANGEROUS"),       #   148건
    "psm1": (False, "DANGEROUS"),
    "bat": (False, "DANGEROUS"),
    "cmd": (False, "DANGEROUS"),
    "vbs": (False, "DANGEROUS"),
    "vbe": (False, "DANGEROUS"),
    "jse": (False, "DANGEROUS"),
    "wsf": (False, "DANGEROUS"),
    "wsh": (False, "DANGEROUS"),
    "lnk": (False, "DANGEROUS"),
    "hta": (False, "DANGEROUS"),
    "reg": (False, "DANGEROUS"),
    "jar": (False, "DANGEROUS"),
}
