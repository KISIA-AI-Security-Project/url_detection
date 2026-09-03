import csv
import gzip
import io
import zlib  # gzip 몸통이 훼손됐을 때 나는 zlib.error를 잡기 위해서만 쓴다(_parse_rows)

from common import LABEL_MALICIOUS, DatasetRow, FetchResult, download

__all__ = ["fetch"]

SOURCE = "phishtank"
FEED_URL = "https://data.phishtank.com/data/online-valid.csv.gz"
SAMPLE_SIZE = 100
USER_AGENT = "phishtank/url-detect" 
CATEGORY = "phishing"
RAW_EXT = "csv.gz"


def fetch() -> FetchResult:
    # 외부 호출: 구조 답 5(User-Agent 필수)·구조 답 2(httpx 기본 timeout)·구조 답 1(실패는 값으로)
    raw_bytes, stats = download(SOURCE, FEED_URL, headers={"User-Agent": USER_AGENT})
    if raw_bytes is None:
        # 구조 답 1: 실패 보고만 하고 build가 다음 출처를 계속한다
        return FetchResult(
            source=SOURCE,
            raw_bytes=b"",
            raw_ext=RAW_EXT,
            rows=[],
            skipped_lines=[],
            freshness="",
            stats=stats,
        )

    parsed, skipped = _parse_rows(raw_bytes)
    # Q11: freshness = 최대 submission_time(명세 신선도 확인 2c)
    freshness = max((r["submission_time"] for r in parsed), default="")
    # 구조 답 13: 안정 정렬로 동률 순서 유지 — sorted는 안정적이며 reverse여도 동률의 원래 순서 유지
    parsed.sort(key=lambda r: r["submission_time"], reverse=True)
    top = parsed[:SAMPLE_SIZE]  # 명세 표: submission_time 최신순 100건

    rows = [
        DatasetRow(
            url=r["url"],  # 명세 규칙: url 원문 무변형
            label=LABEL_MALICIOUS,
            category=CATEGORY,
            source=SOURCE,
            source_id=r["phish_id"],  # Q11: source_id = phish_id 열
            source_status=r["online"],  # 구조 답 8: online 열 값 그대로
            collected_at=stats.completed_at,  # 구조 답 10
        )
        for r in top
    ]
    return FetchResult(
        source=SOURCE,
        raw_bytes=raw_bytes,
        raw_ext=RAW_EXT,
        rows=rows,
        skipped_lines=skipped,
        freshness=freshness,
        stats=stats,
    )


def _parse_rows(raw_bytes: bytes) -> tuple[list[dict[str, str]], list[str]]:
    try:
        text = gzip.decompress(raw_bytes).decode("utf-8", errors="replace")
    except (OSError, EOFError, zlib.error):
        # 해제 실패 세 갈래를 모두 잡는다 — 비 gzip 본문 = gzip.BadGzipFile(OSError 하위), 잘린 파일 = EOFError, 몸통 훼손 = zlib.error.
        # zlib.error를 빼면 build_dataset.py 전체가 traceback으로 죽어 dataset.csv·README.md가 아예 안 생긴다.
        return [], []

    parsed: list[dict[str, str]] = []
    skipped: list[str] = []
    needed = ("phish_id", "url", "submission_time", "online")
    reader = csv.DictReader(io.StringIO(text))
    for record in reader:
        # DictReader는 열 수가 다르면 None 키/값을 만든다 — 그것을 깨진 행으로 판정
        if any(record.get(n) in (None, "") for n in needed) or None in record:
            skipped.append(",".join(v for v in record.values() if isinstance(v, str)))
            continue
        parsed.append({k: v for k, v in record.items() if isinstance(k, str)})
    return parsed, skipped
