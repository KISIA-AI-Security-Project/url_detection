import random

from common import LABEL_MALICIOUS, DatasetRow, FetchResult, download

__all__ = ["fetch"]

FILE_PATH = "phishing-links-INACTIVE.txt"
COMMIT_SHA = "81e4c4db830766896c59c82f4488573ee0810626"
RAW_URL = f"https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/{COMMIT_SHA}/{FILE_PATH}"


SOURCE = "phishing_database"
SAMPLE_SIZE = 100
SEED = 20260825  
CATEGORY = "phishing"
SOURCE_STATUS = "INACTIVE" 
RAW_EXT = "txt"


def fetch() -> FetchResult:
    """INACTIVE 목록을 받아 고정 seed로 SAMPLE_SIZE건을 무작위 추출해 7칸 행으로 돌려준다.

    Q8: 매개변수 없음. freshness = COMMIT_SHA(전체 해시, 구조 답 4).
    """
    # 외부 호출: 구조 답 4(커밋 고정 raw URL, GitHub API 호출 없음)·구조 답 2·구조 답 1
    raw_bytes, stats = download(SOURCE, RAW_URL)
    if raw_bytes is None:
        # 구조 답 1: 실패 보고만 하고 build가 다음 단계로 간다
        return FetchResult(
            source=SOURCE,
            raw_bytes=b"",
            raw_ext=RAW_EXT,
            rows=[],
            skipped_lines=[],
            freshness="",
            stats=stats,
        )

    lines: list[str] = []
    skipped: list[str] = []
    for line in raw_bytes.decode("utf-8", errors="replace").splitlines():
        value = line.strip()
        if not value:
            continue  # 빈 줄은 데이터가 아님
        if value.startswith("#"):
            skipped.append(line)  # 구조 답 12: 주석 등 데이터 아닌 행은 건너뛰고 원문 보존
            continue
        lines.append(value)  # 명세 규칙: 원문 무변형(줄 끝 공백만 제거)

    # Q13·구조 답 3: 전용 Random 인스턴스 + 고정 seed → 어느 환경에서든 같은 100건
    # 행이 SAMPLE_SIZE보다 적으면 sample이 예외를 내므로 있는 만큼만 — verify가 건수로 잡는다
    picked = random.Random(SEED).sample(lines, min(SAMPLE_SIZE, len(lines)))

    rows = [
        DatasetRow(
            url=value,
            label=LABEL_MALICIOUS,
            category=CATEGORY,
            source=SOURCE,
            source_id="",  # Q12: 피드에 식별자 없음
            source_status=SOURCE_STATUS,  # 구조 답 8
            collected_at=stats.completed_at,  # 구조 답 10
        )
        for value in picked
    ]
    return FetchResult(
        source=SOURCE,
        raw_bytes=raw_bytes,
        raw_ext=RAW_EXT,
        rows=rows,
        skipped_lines=skipped,
        freshness=COMMIT_SHA,  # Q12: 커밋 해시(전체)
        stats=stats,
    )
