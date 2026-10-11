# OpenPhish 커뮤니티 피드 — 한 줄에 URL 하나인 텍스트 파일을 받아, 받은 줄 전량을 표본으로 만든다.
# 이 파일은 다운로드·추출·7칸 매핑까지만 하고 파일을 쓰지 않는다. 저장은 build_dataset.py 한 곳에서 한다.
from common import LABEL_MALICIOUS, DatasetRow, FetchResult, download

# 바깥(build_dataset.py)에 내놓는 이름은 fetch 하나뿐이다. 나머지 상수는 이 파일 안에서만 쓴다.
__all__ = ["fetch"]

# 이 출처의 고정 입력값. fetch()는 매개변수 없이 이 상수들만 쓴다 —
# build가 네 출처를 같은 꼴의 fetch()로 순서대로 부를 수 있게 하기 위해서다.
SOURCE = "openphish"    # dataset.csv의 source 칸, raw/ 파일명 앞부분, README 표의 source 칸에 들어가는 출처 이름
FEED_URL = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"  # 받는 파일. GitHub raw이며 12시간마다 통째로 교체된다
CATEGORY = "phishing"   # dataset.csv의 category 칸. 이 출처는 전부 피싱
RAW_EXT = "txt"         # raw/에 저장할 때 붙는 원래 확장자. build가 <SOURCE>_<수집시각>.<RAW_EXT>로 쓴다
# 표본 크기 상수가 없는 이유: 이 출처는 받은 줄 전량(약 350)이 표본이라 자르지 않는다.


def fetch() -> FetchResult:
    """OpenPhish 피드를 받아 URL 줄 전부를 7칸 행으로 바꿔 FetchResult 하나에 담아 돌려준다.

    매개변수가 없는 이유: 입력이 전부 위 상수라서다.
    파일은 쓰지 않는다 — 받은 바이트·표본 행·버린 줄·실측값을 전부 FetchResult에 실어
    build_dataset.py로 넘기고, raw/ 저장과 dataset.csv 병합은 거기서 한다.
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
            freshness="",       # 못 받아서 없음. 성공 경로의 ""(받았는데 원래 없음)와 글자는 같지만 뜻이 다르다
            stats=stats,
        )

    # 이 출처에서 살아남은 줄은 rows에, 버린 줄은 skipped에 나눠 담는다.
    # 둘 다 맨 아래 FetchResult에 실려 build_dataset.py로 넘어간다.
    rows: list[DatasetRow] = []   # dataset.csv에 들어갈 7칸짜리 행
    skipped: list[str] = []       # URL로 쓸 수 없어 버린 줄. build가 raw/<출처>_<시각>_skipped.txt로 남긴다

    # 받은 것은 줄이 나뉘지 않은 바이트 한 덩어리다. 글자로 해석한 뒤(decode) 줄 단위로 자른다(splitlines).
    # errors="replace": UTF-8로 읽히지 않는 바이트가 있어도 멈추지 않고 그 자리를 U+FFFD로 바꿔 읽는다.
    #   바뀐 글자가 dataset.csv에 들어갈 수 있으나, 원본 바이트는 raw/에 그대로 남아 나중에 대조할 수 있다.
    for line in raw_bytes.decode("utf-8", errors="replace").splitlines():
        url = line.strip()  # 앞뒤 공백·탭을 뗀 새 문자열. 원문 line은 그대로 남아 아래 skipped에 쓰인다

        # 관문 1 — 빈 줄은 데이터가 아니다. rows에도 skipped에도 넣지 않아 어느 건수에도 잡히지 않는다.
        if not url:
            continue

        # 관문 2 — http:// 또는 https:// 로 시작하지 않는 줄은 URL로 쓰지 않는다.
        # OpenPhish 피드는 한 줄이 URL 하나이므로, 그 꼴이 아닌 줄은 데이터가 아니라고 본다.
        # 버리되 다듬기 전 원문을 남겨 나중에 사람이 눈으로 확인할 수 있게 한다.
        if not url.startswith(("http://", "https://")):
            skipped.append(line)
            continue

        # 두 관문을 통과한 줄 하나 = dataset.csv 한 행.
        # 7칸 중 줄마다 달라지는 것은 url 하나뿐이고, 나머지는 이 출처에서 전부 같은 값이다.
        rows.append(
            DatasetRow(
                url=url,                          # 받은 문자 그대로. 파싱·정규화하지 않는다(1번 부품의 검증 대상이므로)
                label=LABEL_MALICIOUS,            # 이 단계의 네 출처는 전부 악성
                category=CATEGORY,                # 이 파일 맨 위 상수 "phishing"
                source=SOURCE,                    # 이 파일 맨 위 상수 "openphish"
                source_id="",                     # OpenPhish 피드에는 건별 식별자가 없다
                source_status="",                 # 상태 값도 없다
                collected_at=stats.completed_at,  # 시계를 새로 읽지 않고 다운로드가 끝난 시각을 복사한다.
                                                  # 그래서 이 출처의 모든 행이 같은 시각을 갖는다
            )
        )

    return FetchResult(
        source=SOURCE,
        raw_bytes=raw_bytes,   # 디코드한 문자열이 아니라 받은 바이트 그대로.
                               # build가 이대로 raw/에 저장하고 SHA-256을 계산한다
        raw_ext=RAW_EXT,
        rows=rows,
        skipped_lines=skipped,
        freshness="",          # OpenPhish 피드에는 만든 시각을 적은 줄이 없다.
                               # 실패했을 때의 ""는 "못 받아서 없음", 이 ""는 "받았는데 원래 없음"
        stats=stats,
    )
