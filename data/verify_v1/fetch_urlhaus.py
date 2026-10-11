# URLhaus(abuse.ch) 최근 30일 CSV 피드 — 멀웨어 배포 URL을 받아 dateadded 최신순 100건을 표본으로 만든다.
# 이 파일은 다운로드·추출·7칸 매핑까지만 하고 파일을 쓰지 않는다. 저장은 build_dataset.py 한 곳에서 한다.
import csv   # 데이터 줄을 쉼표로 자를 때 큰따옴표 안의 쉼표를 지키기 위해 쓴다(_parse_rows)
import io    # csv.reader는 파일 객체를 받으므로 문자열 한 줄에 파일 껍데기를 씌우는 데 쓴다(_parse_rows)

from common import LABEL_MALICIOUS, DatasetRow, FetchResult, download

# 바깥(build_dataset.py)에 내놓는 이름은 fetch 하나뿐이다. 밑줄로 시작하는 함수 둘은 이 파일 안에서만 쓴다.
__all__ = ["fetch"]

# 이 출처의 고정 입력값. fetch()는 매개변수 없이 이 상수들만 쓴다 —
# build가 네 출처를 같은 꼴의 fetch()로 순서대로 부를 수 있게 하기 위해서다.
SOURCE = "urlhaus"      # dataset.csv의 source 칸, raw/ 파일명 앞부분, README 표의 source 칸에 들어가는 출처 이름
FEED_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"   # 받는 파일. 인증 없이 받아진다(2026-08-25 실측)
SAMPLE_SIZE = 100       # 표본 건수. dateadded 최신순으로 세운 뒤 앞에서 이만큼 자른다
CATEGORY = "malware"    # dataset.csv의 category 칸. 이 출처는 전부 멀웨어 배포 URL
RAW_EXT = "csv"         # raw/에 저장할 때 붙는 원래 확장자. build가 <SOURCE>_<수집시각>.<RAW_EXT>로 쓴다


def fetch() -> FetchResult:
    """URLhaus CSV를 받아 dateadded 최신순 SAMPLE_SIZE건을 7칸 행으로 바꿔 FetchResult 하나에 담아 돌려준다.

    매개변수가 없는 이유: 입력이 전부 위 상수라서다.
    파일은 쓰지 않는다 — 받은 바이트·표본 행·못 읽은 줄·신선도·실측값을 전부 FetchResult에 실어
    build_dataset.py로 넘기고, raw/ 저장과 dataset.csv 병합·README 기록은 거기서 한다.
    """
    # 외부 호출 한 번. httpx 기본 timeout 그대로, 재시도 없음.
    # 실패해도 예외가 올라오지 않고 (None, 오류를 채운 FetchStats)로 돌아온다 —
    # 한 출처가 실패해도 build가 나머지 출처를 계속 돌릴 수 있게 실패를 값으로 받는다.
    raw_bytes, stats = download(SOURCE, FEED_URL)
    if raw_bytes is None:
        # 다운로드 실패. 표본 없이 실측값(stats: HTTP 상태·걸린 시간·오류 문자열)만 실어 돌려주면
        # build가 README 실패 내역에 적고 다음 출처로 넘어간다.
        return FetchResult(
            source=SOURCE,
            raw_bytes=b"",      # 받은 것이 없다. 성공 경로의 raw_bytes(받은 바이트 그대로)와 구별된다
            raw_ext=RAW_EXT,
            rows=[],            # 표본 0건 — 이유는 stats.error에 남는다
            skipped_lines=[],
            freshness="",       # 못 받아서 없음. 성공 경로에서 "Last updated" 줄을 못 찾았을 때의 ""와 글자는 같지만 뜻이 다르다
            stats=stats,
        )

    # 받은 것은 바이트 한 덩어리다. 글자로 해석해야 줄과 쉼표를 알아볼 수 있다.
    # errors="replace": UTF-8로 읽히지 않는 바이트가 있어도 멈추지 않고 그 자리를 U+FFFD로 바꿔 읽는다.
    #   바뀐 글자가 dataset.csv에 들어갈 수 있으나, 원본 바이트는 raw/에 그대로 남아 나중에 대조할 수 있다.
    text = raw_bytes.decode("utf-8", errors="replace")

    # README의 freshness 칸에 적을 값. 파일 머리 주석의 "Last updated" 줄에서 테두리 #와 앞뒤 공백을 뗀 것.
    # CDN이 옛 사본을 줬는지 나중에 가릴 수 있도록 수집 시각과 나란히 기록만 하고, 오래됐어도 멈추지 않는다.
    freshness = _find_last_updated(text)

    # 데이터 줄을 {열이름: 값} 꾸러미 목록으로 바꾼다.
    # 못 읽은 줄은 원문 그대로 skipped에 담기고, build가 raw/<출처>_<시각>_skipped.txt로 남긴 뒤 README에 건수를 적는다.
    parsed, skipped = _parse_rows(text)

    # dateadded 최신순으로 세운다. 값은 "2026-08-25 11:53:13" 꼴 문자열이라 글자 순서가 곧 시간 순서다.
    # list.sort는 안정 정렬이라 reverse=True여도 같은 시각끼리는 파일에 나온 순서가 그대로 남는다 —
    # 100건 경계에 같은 시각이 걸려도 어느 행이 들어가는지가 매번 같다.
    parsed.sort(key=lambda r: r["dateadded"], reverse=True)

    # 앞에서 SAMPLE_SIZE건. 데이터가 그보다 적으면 있는 만큼만 되고, verify가 건수 불일치로 잡는다.
    top = parsed[:SAMPLE_SIZE]

    # 꾸러미 하나 = dataset.csv 한 행. 줄마다 달라지는 것은 url·source_id·source_status 셋이고 나머지는 이 출처에서 전부 같은 값이다.
    rows = [
        DatasetRow(
            url=r["url"],                     # 받은 문자 그대로. 파싱·정규화하지 않는다(1번 부품의 검증 대상이므로)
            label=LABEL_MALICIOUS,            # 이 단계의 네 출처는 전부 악성
            category=CATEGORY,                # 이 파일 맨 위 상수 "malware"
            source=SOURCE,                    # 이 파일 맨 위 상수 "urlhaus"
            source_id=r["id"],                # URLhaus가 건마다 매긴 번호(CSV id 열)
            source_status=r["url_status"],    # URLhaus가 말하는 상태(online/offline 등). 출처의 주장이지 우리가 확인한 값이 아니다
            collected_at=stats.completed_at,  # 시계를 새로 읽지 않고 다운로드가 끝난 시각을 복사한다.
                                              # 그래서 이 출처의 모든 행이 같은 시각을 갖는다
        )
        for r in top
    ]
    return FetchResult(
        source=SOURCE,
        raw_bytes=raw_bytes,   # 디코드한 문자열이 아니라 받은 바이트 그대로.
                               # build가 이대로 raw/에 저장하고 SHA-256을 계산한다
        raw_ext=RAW_EXT,
        rows=rows,
        skipped_lines=skipped,
        freshness=freshness,   # "Last updated: 2026-08-25 11:53:13 (UTC)" 꼴. 줄을 못 찾았으면 ""
        stats=stats,
    )


def _find_last_updated(text: str) -> str:
    """파일 머리 주석에서 "Last updated" 줄을 찾아 테두리와 공백을 뗀 내용을 돌려준다. 없으면 빈 문자열."""
    for line in text.splitlines():
        if not line.startswith("#"):
            break  # 파일 머리 주석은 #로 시작하는 줄이 연달아 있는 구간이다. 그 구간이 끝나면 더 보지 않는다
        if "Last updated" in line:
            # URLhaus 파일 머리는 #로 테두리를 친 상자라 이 줄이 '# Last updated: ... (UTC)      #' 꼴이다.
            # 바깥 strip()이 줄 끝 공백을 떼야 strip("#")이 뒤쪽 #까지 뗄 수 있고, 안쪽 strip()이 남은 여백을 정리한다.
            return line.strip().strip("#").strip()
    return ""


def _parse_rows(text: str) -> tuple[list[dict[str, str]], list[str]]:
    """URLhaus CSV 본문을 줄마다 {열이름: 값} 꾸러미로 바꾼다.

    돌려주는 것 둘: 읽어낸 꾸러미 목록, 못 읽은 줄의 원문 목록.
    열 이름은 파일에 박아 넣지 않고 파일 머리 주석에서 그때그때 읽는다 —
    URLhaus가 열을 늘리거나 순서를 바꿔도 코드를 고치지 않기 위해서다.
    """
    header: list[str] = []   # 파일이 알려준 열 이름 9개
    body: list[str] = []     # 데이터 줄 원문. 손대지 않고 그대로 쌓는다

    for line in text.splitlines():
        if line.startswith("#"):
            # 파일 머리 주석 중 열 이름이 적힌 줄만 건진다.
            # 그 줄은 "# id,dateadded,url,..." 꼴이므로 앞의 # 를 떼면 "id," 로 시작한다.
            candidate = line.lstrip("#").strip()
            if candidate.startswith("id,"):
                header = [h.strip() for h in candidate.split(",")]
            continue
        if line.strip():
            body.append(line)

    parsed: list[dict[str, str]] = []
    skipped: list[str] = []
    needed = ("id", "dateadded", "url", "url_status")   # 우리가 실제로 쓰는 열

    # 필요한 열 이름을 못 찾았다면 어느 줄도 해석할 수 없다.
    # 여기서 포기하고 데이터 줄 전체를 "못 읽은 줄"로 넘긴다 —
    # 표본이 0건이 되고 verify가 건수 불일치로 잡아준다.
    if not header or any(n not in header for n in needed):
        return parsed, body

    for line in body:
        # 쉼표로 자르되 큰따옴표 안의 쉼표는 건드리지 않는다.
        # tags 열의 "32-bit,elf,mips,Mozi" 같은 값이 여러 칸으로 쪼개지는 것을 막는다.
        # csv.reader는 파일을 받으므로 StringIO로 문자열에 파일 껍데기를 씌우고,
        # 한 줄만 넣었으니 next로 그 하나를 꺼낸다.
        fields = next(csv.reader(io.StringIO(line)))

        # 칸 수가 열 이름 수와 다르면 깨진 줄이다. 원문 그대로 남겨 나중에 확인할 수 있게 한다.
        if len(fields) != len(header):
            skipped.append(line)
            continue

        # 열 이름과 값을 순서대로 짝지어 이름으로 꺼낼 수 있는 꾸러미로 만든다.
        # 이래야 부르는 쪽에서 r["url"] 처럼 쓰고, 열 순서가 바뀌어도 코드가 안 깨진다.
        parsed.append(dict(zip(header, fields)))

    return parsed, skipped
