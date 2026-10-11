import hashlib
import time
from dataclasses import dataclass
from datetime import datetime, timezone
import httpx 


# 다른 모듈에서 from common import *로 가져다 쓸 때, __all__에 없는 이름은 숨긴다.
__all__ = [
    "DatasetRow",
    "FetchStats",
    "FetchResult",
    "ReadmeRow",
    "download",
    "sha256_hex",
    "utc_now_iso",
    "compact_ts",
    "README_COLUMNS",
    "LABEL_MALICIOUS",
]

# README 표의 칸 이름·순서를 한 곳에 고정
README_COLUMNS: tuple[str, ...] = (
    "source",
    "raw_file",
    "sha256",
    "freshness",
    "collected_at",
    "sample_count",
    "skipped_count",
)

# label 어휘를 한 곳에 고정(각 fetch 파일에 문자열을 직접 쓰지 않음)
LABEL_MALICIOUS: str = "malicious"



# ==================================================================== #
# dataset.csv 한 줄을 담는 구조체
# fetch 파일이 URL 하나마다 하나씩 만들고, build_dataset.py가 이것을 CSV한 줄로 쓴다.
# 출처에 없는 값 (Ex: OpenPhish의 source_id, source_status)은 빈 문자열 ""로 둔다.
@dataclass
class DatasetRow:
    url: str            # 제출된 URL 원문.
    label: str          # malicious / benign (지금 데이터셋에서는 전부 LABEL_MALICIOUS)
    category: str       # 출처가 말하는 분류: malware / phishing / benign
    source: str         # 출처 이름: urlhaus / openphish / phishtank / phishing_database / 추후에 정상 URL 출처가 추가
    source_id: str      # 출처 안 식별자 (URLhaus id, PhishTank phish_id). 없으면 ""
    source_status: str  # 출처가 준 상태 값 그대로 (URLhaus url_status, PhishTank online, Phishing.Database는 INACTIVE). 출처의 주장이지 우리가 확인한 값이 아니다. 없으면 ""
    collected_at: str   # 그 출처를 다운로드 완료한 시각. UTC, 예 2026-08-26T01:00:00Z
# ==================================================================== #




# ==================================================================== #
# 다운로드 한 번이 어떻게 끝났는지를 담는 구조체 (출처마다 하나씩 생김)
# download()가 성공/실패 관계없이 채워서 돌려준다.
# build_dataset.py가 읽어 성공 시 그 출처 행들의 collected_at으로 쓰고, 실패 시 error를 README 실패 내역에 적는다.
# None은 "값이 존재하지 않음"(응답 자체가 없었음), 빈 문자열은 "존재하지만 비어 있음"(오류 없음)으로 구분한다.
@dataclass
class FetchStats:
    source: str                     # 출처 이름
    request_url: str                # 다운로드 시도한 URL
    http_status: int | None         # 서버가 준 HTTP 상태 코드, 연결 실패·Timeout으로 응답이 없으면 None
    elapsed_seconds: float | None   # 요청 시작부터 응답 완료까지 걸린 초.
    error: str                      # 실패 이유(httpx 예외 이름과 메시지, 또는 "HTTP 403" 형식). 성공이면 ""
    completed_at: str               # 다운로드 완료 시각.
# ==================================================================== #




# ==================================================================== #
# fetch 파일 하나가 build_dataset.py에 돌려주는 구조체.
# fetch는 파일을 쓰지 않고 다운로드한 원본·뽑은 표본·README에 적을 값을 전부 여기에 담아 돌려준다. 
# build는 이것을 받아 raw/ 저장, dataset.csv 병합, README 작성을 한다.
@dataclass
class FetchResult:
    source: str                     # 출처 이름
    raw_bytes: bytes                # 다운로드한 파일 원본 그대로(바이트열). 압축 파일도 풀지 않은 상태. 다운로드 실패 시 b""
    raw_ext: str                    # 원본 파일의 확장자. "raw/ 파일명 <source>_<시각>.<raw_ext>"에 쓴다
    rows: list[DatasetRow]          # dataset.csv에 넣을 표본 행들
    skipped_lines: list[str]        # 파싱이 안 돼 건너뛴 원문 줄들. build가 "raw/<source>_<시각>_skipped.txt"로 보존하고 README에 건수를 적는다.
    freshness: str                  # README에 적을 신선도 값. URLhaus = 파일 머리의 "Last updated" 줄, PhishTank = 가장 최근 submission_time, Phishing.Database = 받은 커밋 해시, OpenPhish = 내부 시각이 없어 ""
    stats: FetchStats               # 다운로드 한 번이 어떻게 끝났는지를 담는 구조체
# ==================================================================== 



# ==================================================================== #
# README.md 표의 한 줄. 출처마다 하나씩.
# build_dataset.py는 출처 하나가 끝날 때마다 이것을 하나 채워 README 표의 한 줄로 쓴다(구조체 → 글자).
# verify_dataset.py는 README 표를 다시 읽어 이 구조체로 되돌린 뒤(글자 → 구조체), sha256은 raw/ 파일을 다시 계산한 값과, sample_count는 dataset.csv에서 센 건수와 비교한다.
@dataclass
class ReadmeRow:
    source: str                     # 출처 이름
    raw_file: str                   # raw/에 저장한 원본 파일 이름
    sha256: str                     # 그 원본 파일의 SHA-256
    freshness: str                  # 파일 내부 최신 시각(URLhaus,PhishTank)·커밋 해시(Phishing.Database)·OpenPhish는 ""
    collected_at: str               # 다운로드 완료 시각
    sample_count: str               # 해당 출처에서 dataset.csv에 넣은 줄 수
    skipped_count: str              # 파싱이 안 돼 건너뛴 줄 수
# ==================================================================== #





def download(source: str, url: str, headers: dict[str, str] | None = None) -> tuple[bytes | None, FetchStats]: 
    started = time.perf_counter()
    try:
        response = httpx.get(url, headers=headers, follow_redirects=True)
        elapsed = time.perf_counter() - started
        completed_at = utc_now_iso()  # 다운로드 완료 시각
        if response.status_code != 200:
            # 200이 아니면 본문을 원본으로 쓰지 않는다 — 실패로 기록(구조 답 1)
            return None, FetchStats(
                source=source,
                request_url=url,
                http_status=response.status_code,
                elapsed_seconds=elapsed,
                error=f"HTTP {response.status_code}",
                completed_at=completed_at,
            )
        return response.content, FetchStats(
            source=source,
            request_url=url,
            http_status=response.status_code,
            elapsed_seconds=elapsed,
            error="",
            completed_at=completed_at,
        )
    except httpx.HTTPError as exc:
        # Timeout·연결 실패 등 httpx 판정을 그대로 문자열로 기록(구조 답 1·2)
        elapsed = time.perf_counter() - started
        return None, FetchStats(
            source=source,
            request_url=url,
            http_status=None,
            elapsed_seconds=elapsed,
            error=f"{type(exc).__name__}: {exc}",
            completed_at=utc_now_iso(),
        )


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def compact_ts(iso_ts: str) -> str:
    return iso_ts.replace("-", "").replace(":", "")
