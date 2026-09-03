"""build_dataset.py — 진입점. 승인 흐름 (b) 1~4단계: 준비 → 출처별 수집 → 병합·기록 → 검증.

기능 없음, 조립·기록만. 파일 쓰기(raw/·skipped·dataset.csv·README.md)는 이 파일에서만 한다.
구조 답 15: data/verify_v1/ 안에서 `python build_dataset.py`.
"""

import csv
import sys
from dataclasses import replace  # FetchStats를 고치지 않고 error 칸만 바꾼 사본을 만드는 데 쓴다
from pathlib import Path

import fetch_openphish
import fetch_phishing_database
import fetch_phishtank
import fetch_urlhaus
from common import (
    README_COLUMNS,
    DatasetRow,
    FetchResult,
    FetchStats,
    ReadmeRow,
    compact_ts,
    sha256_hex,
)
from verify_dataset import verify

__all__ = ["main"]

# Q15: 스크립트 파일 위치 기준 경로 — 실행 위치가 어긋나도 산출물은 data/verify_v1/에 생긴다
BASE_DIR = Path(__file__).resolve().parent
RAW_DIR = BASE_DIR / "raw"
DATASET_PATH = BASE_DIR / "dataset.csv"
README_PATH = BASE_DIR / "README.md"
# Q15: 출처 표 순서 고정(승인 흐름 2단계: URLhaus → OpenPhish → PhishTank → Phishing.Database)
FETCHES = [
    fetch_urlhaus.fetch,
    fetch_openphish.fetch,
    fetch_phishtank.fetch,
    fetch_phishing_database.fetch,
]


def main() -> int:
    """승인 흐름 1~4단계 실행. 0 = 4출처 수집 + verify 전 항목 통과, 1 = 실패·중단 하나라도 발생(Q14)."""
    # 1. 준비 — raw/ 폴더 생성 확인. 실패(권한 등) 시 즉시 중단·오류 보고
    try:
        RAW_DIR.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"[중단] raw/ 폴더를 만들 수 없음: {exc}")
        return 1

    all_rows: list[DatasetRow] = []
    readme_rows: list[ReadmeRow] = []
    failures: list[FetchStats] = []

    # 2. 출처별 수집 — 표 순서로, 한 출처 실패 시 나머지 계속(구조 답 1)
    for fetch in FETCHES:
        result: FetchResult = fetch()  # 2a 다운로드 + 2c 신선도 + 2d 추출 + 2e 매핑은 fetch 안에서
        stats = result.stats
        elapsed = f"{stats.elapsed_seconds:.2f}s" if stats.elapsed_seconds is not None else "-"
        if stats.error:
            # 구조 답 1: 실패 보고만 하고 다음 출처 계속. README 행은 비움(Q7)
            print(f"[실패] {result.source}: {stats.error} (HTTP {stats.http_status}, {elapsed})")
            failures.append(stats)
            readme_rows.append(
                ReadmeRow(
                    source=result.source,
                    raw_file="",
                    sha256="",
                    freshness="",
                    collected_at=stats.completed_at,
                    sample_count="",
                    skipped_count="",
                )
            )
            continue

        # 2b 원본 보존 — 실패 시 전체 중단(원본 없이는 재현 불가)
        try:
            raw_file, digest = _save_raw(result)
            _save_skipped(result)  # 구조 답 12: 건너뛴 행 원문 보존
        except OSError as exc:
            print(f"[중단] {result.source} 원본 저장 실패: {exc}")
            return 1

        print(
            f"[수집] {result.source}: HTTP {stats.http_status}, {elapsed}, "
            f"{len(result.rows)}건, 건너뜀 {len(result.skipped_lines)}건 → {raw_file}"
        )
        all_rows.extend(result.rows)
        readme_rows.append(
            ReadmeRow(
                source=result.source,
                raw_file=raw_file,
                sha256=digest,
                freshness=result.freshness,
                collected_at=stats.completed_at,  # 구조 답 10
                sample_count=str(len(result.rows)),
                skipped_count=str(len(result.skipped_lines)),
            )
        )
        if not result.rows:
            # 오류 없이 0건 — 빈 본문이 왔거나(HTTP 200에 0바이트) 해제·해석에 실패한 경우다.
            # 정상적으로 빈 파일이 온 것과 기록만으로 구별되도록 실패 내역에 이유를 남기고 종료 코드를 1로 만든다.
            # raw/ 저장과 README 표 행은 위에서 정상 수집과 똑같이 남겼다(원본을 확인할 수 있어야 하므로).
            # stats 자체는 건드리지 않고 error 칸만 채운 사본을 failures에 넣는다 — README 실패 내역이 이 목록을 읽는다.
            reason = (
                f"표본 0건 — 응답 본문 {len(result.raw_bytes)}바이트, "
                f"건너뜀 {len(result.skipped_lines)}건"
            )
            print(f"[실패] {result.source}: {reason}")
            failures.append(replace(stats, error=reason))

    # 3. 병합·기록 — 출처 순서로 이어붙임(중복 제거 안 함). 실패 시 중단·보고
    try:
        _write_dataset(all_rows)
        _write_readme(readme_rows, failures)
    except OSError as exc:
        print(f"[중단] dataset.csv/README.md 쓰기 실패: {exc}")
        return 1
    print(f"[기록] {DATASET_PATH.name} {len(all_rows)}행, {README_PATH.name}")

    # 4. 검증 — build 말미 자동 호출. 실패 시 파일은 그대로 두고 보고만
    problems = verify(BASE_DIR)
    for message in problems:
        print(f"[검증 실패] {message}")
    if not problems:
        print("[검증] 전 항목 통과")

    # Q14: 출처 실패·검증 실패 중 하나라도 있으면 1
    return 0 if not failures and not problems else 1


def _save_raw(result: FetchResult) -> tuple[str, str]:
    """원본 바이트를 raw/에 받은 그대로 저장하고 (저장 파일명, SHA-256)을 돌려준다(Q16, 흐름 2b).

    구조 답 11: 파일명 = <source>_<수집일시 압축형>.<원래 확장자>. PhishTank는 .gz 그대로.
    """
    raw_name = f"{result.source}_{compact_ts(result.stats.completed_at)}.{result.raw_ext}"
    (RAW_DIR / raw_name).write_bytes(result.raw_bytes)  # 파일 쓰기: 구조 답 11
    return raw_name, sha256_hex(result.raw_bytes)  # Q5: README 기록용 다이제스트


def _save_skipped(result: FetchResult) -> str:
    """건너뛴 행 원문을 raw/<source>_<수집일시>_skipped.txt에 보존하고 파일명을 돌려준다(Q16, 구조 답 12).

    건너뛴 행이 없으면 파일을 만들지 않고 빈 문자열을 돌려준다.
    """
    if not result.skipped_lines:
        return ""
    name = f"{result.source}_{compact_ts(result.stats.completed_at)}_skipped.txt"
    # 파일 쓰기: 구조 답 12 — 원문 그대로, 줄 단위
    (RAW_DIR / name).write_text("\n".join(result.skipped_lines) + "\n", encoding="utf-8")
    return name


def _write_dataset(rows: list[DatasetRow]) -> None:
    """dataset.csv를 쓴다(Q16·Q17): csv.writer 기본 quoting, UTF-8, newline="", 첫 행 7칸 헤더.

    값은 무변형 — 쉼표·따옴표는 표준 csv 규칙으로만 감싼다(명세의 url 원문 보존).
    """
    # 파일 쓰기: 흐름 3단계 dataset.csv
    with DATASET_PATH.open("w", encoding="utf-8", newline="") as fp:
        writer = csv.writer(fp)
        writer.writerow(
            ["url", "label", "category", "source", "source_id", "source_status", "collected_at"]
        )
        for row in rows:
            writer.writerow(
                [
                    row.url,
                    row.label,
                    row.category,
                    row.source,
                    row.source_id,
                    row.source_status,
                    row.collected_at,
                ]
            )


def _write_readme(rows: list[ReadmeRow], failures: list[FetchStats]) -> None:
    """README.md를 쓴다(Q16·Q7): freshness 뜻 한 줄 → README_COLUMNS 표 → 실패 내역 절.

    표 형식은 verify_dataset._read_readme가 읽는 마크다운 표(| 구분)와 맞춘다.
    """
    lines: list[str] = ["# verify_v1 — 검증용 데이터셋 수집 기록", ""]
    # Q7 조건: 표 바로 위에 freshness 칸의 뜻 한 줄
    lines.append(
        "freshness = 파일 내부 최신 시각(URLhaus·PhishTank) 또는 커밋 해시(Phishing.Database), "
        "OpenPhish는 없음"
    )
    lines.append("")
    lines.append("| " + " | ".join(README_COLUMNS) + " |")
    lines.append("|" + "---|" * len(README_COLUMNS))
    for row in rows:
        cells = [
            row.source,
            row.raw_file,
            row.sha256,
            row.freshness,
            row.collected_at,
            row.sample_count,
            row.skipped_count,
        ]
        # 표 칸 안의 '|'는 표 구조를 깨므로 이스케이프(값 자체는 README 기록용)
        lines.append("| " + " | ".join(c.replace("|", "\\|") for c in cells) + " |")
    lines.append("")
    # Q7: 실패한 출처는 표 아래 "실패 내역" 절에 오류 문자열로
    lines.append("## 실패 내역")
    lines.append("")
    if failures:
        for stats in failures:
            lines.append(
                f"- {stats.source}: {stats.error} (HTTP {stats.http_status}, "
                f"{stats.elapsed_seconds}s, {stats.completed_at}, {stats.request_url})"
            )
    else:
        lines.append("- 없음")
    lines.append("")
    # 파일 쓰기: 흐름 3단계 README.md
    README_PATH.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
