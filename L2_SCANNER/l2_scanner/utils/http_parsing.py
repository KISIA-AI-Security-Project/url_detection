"""HTTP 값 파싱 공통 유틸.

[왜 이 모듈이 필요한가]
같은 파싱 작업이 프로젝트 여러 곳에서 반복된다.
  - Content-Disposition 파싱  → Collector(download 트리 채움)와 L2-H-07(강제 다운로드)
  - MIME 본체 추출           → Collector(download.mime_type)와 L2-H-05(Content-Type 불일치)
  - eTLD+1 추출              → L2-H-02(도메인 변경), L2-H-04(단축 URL), l2_scanner(target.final_etld1)

각자 따로 구현하면 언젠가 한쪽만 수정되어 "같은 헤더를 놓고 Collector와 Analyzer의
해석이 다른" 버그가 생긴다. 그래서 파싱 로직을 이 한 파일로 모으고 전원이 공유한다.

이 모듈의 함수들은 전부 순수 함수다(네트워크 X, 파일 X, 전역 상태 X).
문자열을 넣으면 결과가 나올 뿐이므로 단위 테스트가 쉽다. → tests/test_http_parsing.py
"""

from urllib.parse import unquote, urlsplit

import tldextract


def _split_params(value: str) -> list[str]:
    """헤더 값을 세미콜론으로 토큰 분리한다 — 단, 따옴표("...") 안의 세미콜론은 제외.

    단순 value.split(";")은 filename="payload;evil.exe" 를 filename="payload 에서
    잘라 진짜 확장자(.exe)를 놓친다. 브라우저는 따옴표를 존중해 payload;evil.exe로
    저장하므로, 그 차이가 위험 확장자 탐지(L2-H-06/07)의 우회 통로가 된다. (팀 리뷰 반영)
    한계: 따옴표 안 백슬래시 이스케이프(\\")까지는 다루지 않는다 — 관대한 파싱의 범위.
    """
    parts = []
    buf = []
    in_quotes = False
    for ch in value:
        if ch == '"':
            in_quotes = not in_quotes
            buf.append(ch)
        elif ch == ";" and not in_quotes:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    return parts


def parse_content_disposition(value: str) -> dict:
    """Content-Disposition 헤더 값에서 '처리 유형'과 '파일명'을 뽑는다.

    입력 예시 → 출력:
        'attachment; filename="report.exe"'
            → {"type": "attachment", "filename": "report.exe"}
        'inline; filename=doc.pdf'
            → {"type": "inline", "filename": "doc.pdf"}
        "attachment; filename*=UTF-8''%EC%95%85%EC%84%B1.exe"
            → {"type": "attachment", "filename": "악성.exe"}   ← 퍼센트 인코딩 복원

    [헤더 문법 배경지식]
    Content-Disposition은 "유형; 파라미터; 파라미터..." 구조다.
      - 유형: attachment(다운로드 강제) 또는 inline(화면에 표시)
      - 파일명 파라미터는 두 가지 표기가 있다:
          filename="이름"           ← 고전 표기 (ASCII 전제)
          filename*=UTF-8''%..%..  ← RFC 5987 확장 표기 (비ASCII 파일명용, 퍼센트 인코딩)
      - RFC 6266 규칙: 두 표기가 같이 오면 filename*이 우선이다.
        브라우저가 그렇게 동작하므로, 스캐너가 filename*을 못 읽으면
        공격자는 filename에 가짜 이름(decoy.txt)을, filename*에 진짜 이름(real.exe)을
        넣는 방식으로 위험 확장자 탐지를 회피할 수 있다. 그래서 반드시 해석한다.
    """
    disp_type = None       # attachment / inline (소문자 정규화)
    filename = None        # filename= 고전 표기로 얻은 이름
    filename_star = None   # filename*= 확장 표기로 얻은 이름 (있으면 이쪽이 우선)

    # 세미콜론으로 토큰 분리: 'attachment; filename="a.exe"' → ["attachment", 'filename="a.exe"']
    # 따옴표 안의 세미콜론(filename="a;b.exe")은 구분자가 아니다 — _split_params 참고
    parts = [p.strip() for p in _split_params(value)]

    if parts:
        disp_type = parts[0].lower() or None   # 첫 토큰 = 유형. 대소문자 변형(Attachment) 흡수

    for token in parts[1:]:
        lower = token.lower()   # 파라미터 이름도 대소문자 무관 (FILENAME= 허용)

        if lower.startswith("filename*="):
            # RFC 5987 형식: charset'language'percent-encoded
            # 예: UTF-8''%EC%95%85%EC%84%B1.exe → charset="UTF-8", 인코딩된 본문="%EC%95%85..."
            raw_val = token[len("filename*="):].strip()
            pieces = raw_val.split("'", 2)   # 작은따옴표 2개를 기준으로 3조각
            if len(pieces) == 3:
                charset = pieces[0] or "utf-8"   # charset 생략 시 utf-8로 간주
                encoded = pieces[2]
            else:
                # 형식이 어긋난 값 → utf-8 가정으로 최대한 복원 (관대한 파싱)
                charset, encoded = "utf-8", raw_val.strip("'\"")
            try:
                filename_star = unquote(encoded, encoding=charset, errors="replace")
            except LookupError:
                # 존재하지 않는 charset을 선언한 경우 → utf-8로 폴백
                filename_star = unquote(encoded)

        elif lower.startswith("filename="):
            # 고전 표기: 값의 앞뒤 따옴표('..' 또는 "..")와 공백을 벗겨낸다
            filename = token[len("filename="):].strip().strip("'\"")

    # RFC 6266: filename*이 있으면 그것이 진짜 파일명
    return {"type": disp_type, "filename": filename_star or filename}


def extension_from_filename(filename: str) -> str | None:
    """파일명에서 확장자를 뽑는다. 마지막 점(.) 뒤를 소문자로. 점이 없으면 None.

    예시:
        "report.EXE"      → "exe"     (대소문자 정규화)
        "invoice.pdf.exe" → "exe"     (이중 확장자 위장 → 마지막 것)
        "README"          → None      (확장자 부재가 확실 → None)

    '마지막 점 뒤'를 쓰는 이유: 운영체제가 파일을 실행할 때 보는 기준과 같다.
    invoice.pdf.exe는 PDF처럼 보이지만 실제로는 exe로 실행되므로,
    위험 파악 목적에는 마지막 확장자가 정확하다.
    """
    if not filename or "." not in filename:
        return None
    ext = filename.rsplit(".", 1)[1].strip().lower()
    return ext or None   # "name." 처럼 점 뒤가 비어 있으면 None


def filename_from_url(url: str) -> str | None:
    """URL 경로의 마지막 조각을 파일명 후보로 뽑는다. 확장자 표기(.)가 없으면 None.

    예시:
        "http://evil.example/payload.ps1"   → "payload.ps1"
        "http://x/%EC%95%85%EC%84%B1.exe"   → "악성.exe"   (퍼센트 인코딩 복원)
        "http://x/search"                   → None         (점 없음 = 파일로 안 봄)
        "http://x/a.exe?token=1.2"          → "a.exe"      (쿼리스트링은 경로가 아님)

    [왜 필요한가]
    Content-Disposition 헤더 없이 직링크로 파일을 배포하는 경우
    (http://evil/payload.ps1) 파일명 정보가 헤더에 전혀 없다.
    이때 브라우저는 URL 경로명을 저장 파일명으로 쓴다 → 스캐너도 같은 기준을 쓴다.
    이 fallback이 없으면 직링크 스크립트 파일(ps1/bat 등)은 확장자도 없고
    magic 서명도 약해서(텍스트) L2-H-06이 완전히 놓친다.
    """
    if not url:
        return None
    path = urlsplit(url).path                       # 쿼리스트링·프래그먼트 제외한 순수 경로
    base = unquote(path.rsplit("/", 1)[-1]).strip() # 마지막 / 뒤 조각 + 퍼센트 인코딩 복원
    return base if "." in base else None            # 점이 없으면 파일명 후보로 안 씀 (일반 페이지 경로)


def split_mime(content_type: str | None) -> str | None:
    """Content-Type 값에서 파라미터를 제거하고 MIME 본체만 소문자로 돌려준다.

    예시:
        "Text/HTML; charset=UTF-8" → "text/html"
        None                       → None

    Content-Type은 "본체; 파라미터" 구조인데(charset 등),
    유형 비교에는 본체만 필요하므로 세미콜론 앞만 취한다.
    """
    if not content_type:
        return None
    mime = content_type.split(";")[0].strip().lower()
    return mime or None


def etld1(url: str) -> str:
    """URL에서 '소유 단위 도메인'(eTLD+1)을 뽑는다.

    예시:
        "https://login.example.co.kr/a" → "example.co.kr"
        "https://www.google.com"        → "google.com"
        "http://93.184.216.34/"         → "93.184.216.34"  (IP는 그대로)

    [왜 tldextract를 쓰는가]
    점(.)으로 직접 자르면 example.co.kr에서 co.kr을 도메인으로 오인한다.
    co.kr, github.io 같은 '복합 공공 접미사'는 규칙이 아니라 목록(Public Suffix List)으로만
    구분할 수 있고, tldextract가 그 목록을 내장하고 있다.

    suffix가 없는 호스트(IP 주소, localhost)는 도메인부 전체를 그대로 반환한다.
    → IP로의 리다이렉트도 '소유자 변경'으로 셀 수 있게 하기 위함 (L2-H-02에서 중요).
    """
    ext = tldextract.extract(url)
    if not ext.suffix:
        return ext.domain
    return f"{ext.domain}.{ext.suffix}"
