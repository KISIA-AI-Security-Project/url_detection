"""
그룹 C — 링크·파일 분석

C-1 파일 다운로드 / C-2 이중 확장자 / C-3 단축 URL

모든 판정은 0단계(parsing.py)가 만든 ParseResult만 입력으로 받으며,
파일을 실제로 받아 보거나 서버의 Content-Type을 확인하지 않는다.
"""

from __future__ import annotations

import logging
from typing import Iterator
from urllib.parse import unquote

from l0.common import (
    GROUP_C_DOUBLE_EXTENSION,
    GROUP_C_FILE_DOWNLOAD,
    GROUP_C_SHORT_URL,
)
from l0.models import AnalysisRecord, detected, not_applicable
from l0.parsing import ParseResult
from l0.data.extensions import EXTENSION_RISK_MAP, EXTENSION_RISK_VERSION
from l0.data.shorteners import SHORTENER_DOMAINS, SHORTENERS_VERSION

logger = logging.getLogger(__name__)

# 검사 대상이 경로에서 나왔는지 쿼리 값에서 나왔는지.
# 판정은 양쪽 모두에서 하지만, 목록 밖 확장자 기록은 경로에서만 한다.
_LOCATION_PATH = "PATH"
_LOCATION_QUERY = "QUERY"

# C-2: 이중 확장자로 보려면 최소 세 토큰이 필요하다.
# 파일명 + 위장 확장자 + 실제 확장자. 코퍼스에서 경로 파일명의 98.24%가
# 토큰 2개(file.ext)라 이 조건만으로 대부분이 걸러진다.
_MIN_TOKENS_FOR_DOUBLE_EXTENSION = 3


# ---------------------------------------------------------------------------
# C-1. 파일 다운로드
# ---------------------------------------------------------------------------
def check_file_download(result: ParseResult) -> AnalysisRecord:
    """
    일반 브라우징에서 렌더링되지 않는, 즉 다운로드를 유도하는 파일인지 판정한다.

    경로의 마지막 세그먼트와 쿼리 파라미터 값에서 확장자를 뽑아
    EXTENSION_RISK_MAP의 web_safe를 본다. False면 탐지다.

    [MIME을 쓰지 않는 이유]
    mimetypes.guess_type()은 실행 환경의 MIME 등록 정보를 읽는다. Windows는
    레지스트리, Linux는 /etc/mime.types다. 같은 .exe가 환경에 따라
    application/x-msdownload와 application/octet-stream으로 갈리고, .hwp는
    한컴오피스가 깔린 PC에서만 값이 나온다. 개발 PC와 Lambda가 같은 URL을
    다르게 판정하게 되므로 쓰지 않는다. 참고값으로 레코드에 남기지도 않는다 —
    권위 있어 보이지만 재현되지 않는 값이라 오히려 해롭다.

    또한 MIME 화이트리스트 방식은 guess_type()이 None을 돌려주는 확장자를
    전부 비인가로 떨어뜨린다. 코퍼스에서 .php가 경로 확장자의 51.5%(165,441건)
    인데 guess_type("login.php")는 None이다. 정상 사이트가 대량 오탐된다.
    """
    name = GROUP_C_FILE_DOWNLOAD
    parsed = result.parsed
    list_version = {"extension_risk": EXTENSION_RISK_VERSION}

    if parsed is None:
        return not_applicable(name, list_version=list_version)

    # 목록 밖 확장자는 판정하지 않되 첫 번째 것을 기록해 둔다.
    # 모르는 확장자를 모아 두면 목록 보강 근거가 된다. 코퍼스에서 IoT 봇넷
    # 아키텍처명(mips, arm7 등 약 1,329건)을 찾아낸 것이 정확히 이 방식이었다.
    unknown_extension: str | None = None

    for location, candidate in _iter_candidates(result):
        extension = _extension_of(candidate)
        if extension is None:
            continue

        entry = EXTENSION_RISK_MAP.get(extension)
        if entry is None:
            # 쿼리 값의 목록 밖 확장자는 기록하지 않는다. 상위가 com(6,261),
            # c(3,487), 타임스탬프 숫자라 노이즈가 압도적이어서 목록 보강
            # 근거로 쓸 수 없다.
            if location == _LOCATION_PATH and unknown_extension is None:
                unknown_extension = extension
            continue

        web_safe, _role = entry
        if web_safe:
            continue

        return detected(
            name,
            {
                "matched_string": candidate,
                "extension": extension,
                "location": location,
            },
            list_version=list_version,
        )

    if unknown_extension is not None:
        return not_applicable(
            name,
            value={"extension": unknown_extension, "location": _LOCATION_PATH},
            list_version=list_version,
        )

    return not_applicable(name, list_version=list_version)


# ---------------------------------------------------------------------------
# C-2. 이중 확장자
# ---------------------------------------------------------------------------
def check_double_extension(result: ParseResult) -> AnalysisRecord:
    """
    위장용 확장자 뒤에 실제 확장자를 붙인 파일명인지 판정한다.

    salary_list.xlsx.exe 처럼 사용자가 문서로 오인하게 만드는 형태를 잡는다.

    [점의 개수가 기준이 아니다]
    점이 여러 개인 정상 파일명이 흔하다. jquery.min.js, archive.tar.gz,
    v1.2.3.zip은 전부 토큰이 3개 이상이다. 이상한 것은 개수가 아니라 순서다 —
    사용자가 안심할 만한 것(DECEPTIVE) 뒤에 실행되는 것(DANGEROUS)이 오는 조합이다.

    [C-1과 동시에 탐지되는 것은 의도된 동작이다]
    salary_list.xlsx.exe는 C-1(exe가 web_safe=False)에도 걸린다. 두 판정이
    말하는 바가 다르다. C-1은 "실행 파일을 받게 한다", C-2는 "문서인 척했다"다.
    또 C-2만 잡는 경우도 있다 — logo.png.js는 js가 정상 웹 리소스라 C-1을
    통과하지만 이중 확장자다.

    [예외 목록을 두지 않는다]
    코퍼스 상위 150개 조합을 검증한 결과 규칙에 걸리는 것은 pdf.lnk 5건뿐이고
    그것은 실제 공격이었다. com.html(513), github.io(475), pdf.html(119),
    min.js(87)는 전부 통과한다. 예외가 필요하다는 증거가 없으므로 만들지 않는다.
    """
    name = GROUP_C_DOUBLE_EXTENSION
    parsed = result.parsed
    list_version = {"extension_risk": EXTENSION_RISK_VERSION}

    if parsed is None:
        return not_applicable(name, list_version=list_version)

    for location, candidate in _iter_candidates(result):
        # 빈 토큰은 버린다. .file.exe(숨김 파일)와 file..exe가 모두 두 토큰이
        # 되어 대상에서 빠진다. 둘 다 실제 확장자는 하나뿐이다.
        tokens = [token for token in candidate.split(".") if token]
        if len(tokens) < _MIN_TOKENS_FOR_DOUBLE_EXTENSION:
            continue

        fake_extension = tokens[-2].lower()
        real_extension = tokens[-1].lower()

        fake_entry = EXTENSION_RISK_MAP.get(fake_extension)
        real_entry = EXTENSION_RISK_MAP.get(real_extension)
        if fake_entry is None or real_entry is None:
            continue

        if fake_entry[1] != "DECEPTIVE" or real_entry[1] != "DANGEROUS":
            continue

        return detected(
            name,
            {
                "matched_string": candidate,
                "fake_extension": fake_extension,
                "real_extension": real_extension,
                "location": location,
            },
            list_version=list_version,
        )

    return not_applicable(name, list_version=list_version)


# ---------------------------------------------------------------------------
# C-3. 단축 URL
# ---------------------------------------------------------------------------
def check_short_url(result: ParseResult) -> AnalysisRecord:
    """
    단축 URL 서비스를 거치는 링크인지 판정한다.

    [무엇을 증거로 남기는가]
    단축 URL은 최종 목적지를 문자열에서 감춘다. 즉 L0의 다른 모든 판정이
    무력화된다는 사실 자체가 증거다. 단축 URL이라는 것이 곧 악성이라는 뜻은
    아니다 — 정상 서비스도 대량으로 쓴다.

    [리다이렉트를 따라가지 않는다]
    L0의 절대 원칙이다. 문자열 패턴으로 가능성만 표시하고 실제 목적지 확인은
    L1~L2로 넘긴다.

    [A-3(무료 발급 도메인)과 구분한다]
    코퍼스에서 짧은 도메인 + 짧은 경로로 추출하면 r2.dev, github.io, web.app,
    pages.dev 같은 무료 발급 도메인이 섞여 나온다. 그쪽은 A-3의 영역이므로
    shorteners.json에 들어오면 동기화 단계에서 걸러야 한다.
    """
    name = GROUP_C_SHORT_URL
    extracted = result.extracted
    list_version = {"shorteners": SHORTENERS_VERSION}

    # IP 호스트, 로컬 도메인, PSL에 없는 문자열이 여기서 걸러진다.
    if extracted is None or not extracted.registered_domain:
        return not_applicable(name, list_version=list_version)

    provider = extracted.registered_domain.lower()
    if provider not in SHORTENER_DOMAINS:
        return not_applicable(name, list_version=list_version)

    # value를 문자열이 아니라 dict로 두는 이유는 A-3과 같다.
    # 나중에 필드를 늘릴 때 소비자 쪽을 깨뜨리지 않기 위함이다.
    return detected(name, {"provider": provider}, list_version=list_version)


def _iter_candidates(result: ParseResult) -> Iterator[tuple[str, str]]:
    """
    확장자를 찾을 문자열을 (위치, 문자열) 순서로 내놓는다.

    경로를 먼저 본다. 확장자 사이에 근거 있는 위험도 서열이 없으므로 우선순위
    규칙을 두지 않고 첫 번째로 걸리는 것을 채택한다.
    """
    parsed = result.parsed
    if parsed is None:
        return

    # ada는 pathname의 퍼센트 인코딩을 풀지 않는다. 코퍼스에 %XX가 남은 경로가
    # 13,903건(1.38%) 있고, 풀지 않으면 setup%2Eexe에서 확장자를 뽑지 못한다.
    #
    # 한 번만 푼다. 브라우저가 한 번만 풀기 때문이다. %252E가 점이 되려면 서버
    # 애플리케이션이 한 번 더 푸는 버그가 있어야 하고, 그건 URL 표준의 문제가
    # 아니라 이중 디코딩 취약점이라 L2 이후의 몫이다. 끝까지 푸는 방식은
    # 파일명에 %2E라는 글자가 진짜 들어간 경우를 망가뜨린다.
    segment = unquote(parsed.pathname).rsplit("/", 1)[-1]
    if segment:
        yield _LOCATION_PATH, segment

    # query 값은 parse_search_params가 이미 디코드해 두었으므로 다시 풀지 않는다.
    # 키는 보지 않는다. ?file=setup.exe 형태를 잡는 것이 목적이다.
    for values in result.query.values():
        for value in values:
            if value:
                yield _LOCATION_QUERY, value


def _extension_of(candidate: str) -> str | None:
    """마지막 점 뒤를 소문자 확장자로 돌려준다. 없으면 None."""
    if "." not in candidate:
        return None
    extension = candidate.rsplit(".", 1)[-1].lower()
    return extension or None


# registry가 순차 실행할 때 참조하는 목록.
# 각 함수는 ParseResult 하나만 받고 AnalysisRecord 하나를 돌려주는 동일한 형태다.
GROUP_C_DETECTORS = (
    check_file_download,
    check_double_extension,
    check_short_url,
)
