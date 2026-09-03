"""verify_dataset.py — 검증 조건 점검(Q18·Q19). build 말미 자동 호출 + 단독 재실행(승인 흐름 4).

조건(구조 답 14 반영본): 고정 3출처 정확히 100 · OpenPhish는 README 건수와 일치 ·
label·category·source·collected_at 빈칸 없음 · README SHA-256이 raw/ 파일과 일치.
실패해도 파일은 건드리지 않고 보고만 한다.
"""

import csv
import sys
from pathlib import Path

from common import README_COLUMNS, DatasetRow, ReadmeRow, sha256_hex

__all__ = ["verify", "main"]

# Q18: 수정된 명세 검증 조건 문장과 1:1
EXPECTED_EXACT = {"urlhaus": 100, "phishtank": 100, "phishing_database": 100}
REQUIRED_FIELDS = ("label", "category", "source", "collected_at")


def verify(base_dir: Path) -> list[str]:
    """base_dir의 dataset.csv·README.md·raw/를 읽어 검증 조건별 실패 메시지 목록을 돌려준다.

    빈 리스트 = 전부 통과. 값으로 돌려주는 이유: build 자동 호출과 단독 실행을 겸하기 위함(Q18).
    """
    dataset_path = base_dir / "dataset.csv"
    readme_path = base_dir / "README.md"
    raw_dir = base_dir / "raw"

    problems: list[str] = []
    # 입력 파일이 없으면 이후 점검이 무의미하므로 여기서 보고하고 끝낸다
    if not dataset_path.is_file():
        problems.append(f"dataset.csv 없음: {dataset_path}")
    if not readme_path.is_file():
        problems.append(f"README.md 없음: {readme_path}")
    if problems:
        return problems

    # dataset.csv 읽기 — 헤더 이름으로 7칸 매핑(csv 표준 규칙, 값 무변형)
    rows: list[DatasetRow] = []
    with dataset_path.open("r", encoding="utf-8", newline="") as fp:
        for record in csv.DictReader(fp):
            rows.append(
                DatasetRow(
                    url=record.get("url", "") or "",
                    label=record.get("label", "") or "",
                    category=record.get("category", "") or "",
                    source=record.get("source", "") or "",
                    source_id=record.get("source_id", "") or "",
                    source_status=record.get("source_status", "") or "",
                    collected_at=record.get("collected_at", "") or "",
                )
            )
    readme_rows = _read_readme(readme_path)

    # 검증 조건 한 가지당 점검 함수 하나(Q19)
    problems.extend(_check_counts(rows, readme_rows))
    problems.extend(_check_required_fields(rows))
    problems.extend(_check_sha256(readme_rows, raw_dir))
    return problems


def main() -> int:
    """단독 실행용: 이 파일 위치 기준으로 verify를 돌리고 항목별 통과/실패를 출력, 0/1 반환."""
    problems = verify(Path(__file__).resolve().parent)
    if not problems:
        print("[검증] 전 항목 통과")
        return 0
    for message in problems:
        print(f"[검증 실패] {message}")
    return 1


def _read_readme(readme_path: Path) -> list[ReadmeRow]:
    """README.md의 마크다운 표(README_COLUMNS 머리)를 ReadmeRow 목록으로 읽는다(Q19).

    build._write_readme가 쓴 형식만 읽는다: 머리 줄 → 구분 줄 → 데이터 줄. 다른 줄은 무시.
    """
    rows: list[ReadmeRow] = []
    in_table = False
    for line in readme_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            in_table = False  # 표가 끝남
            continue
        cells = [c.strip().replace("\\|", "|") for c in stripped.strip("|").split("|")]
        if not in_table:
            # README_COLUMNS와 같은 머리 줄을 만나면 표 시작
            if tuple(cells) == README_COLUMNS:
                in_table = True
            continue
        if all(set(c) <= set("-: ") for c in cells):
            continue  # 구분 줄
        if len(cells) != len(README_COLUMNS):
            continue  # 형식이 다른 줄은 표 행으로 보지 않는다
        rows.append(ReadmeRow(*cells))
    return rows


def _check_counts(rows: list[DatasetRow], readme_rows: list[ReadmeRow]) -> list[str]:
    """고정 3출처는 정확히 100건, OpenPhish는 README sample_count와 dataset 건수 일치(구조 답 14)."""
    problems: list[str] = []
    counts: dict[str, int] = {}
    for row in rows:
        counts[row.source] = counts.get(row.source, 0) + 1

    for source, expected in EXPECTED_EXACT.items():
        actual = counts.get(source, 0)
        if actual != expected:
            problems.append(f"건수: {source} = {actual} (기대 {expected})")

    # OpenPhish: README에 기록한 받은 건수와 dataset.csv 건수 대조
    readme_openphish = [r for r in readme_rows if r.source == "openphish"]
    actual_openphish = counts.get("openphish", 0)
    if not readme_openphish or not readme_openphish[0].sample_count:
        problems.append(f"건수: openphish README 기록 없음 (dataset {actual_openphish})")
    elif readme_openphish[0].sample_count != str(actual_openphish):
        problems.append(
            f"건수: openphish dataset {actual_openphish} ≠ README {readme_openphish[0].sample_count}"
        )
    return problems


def _check_required_fields(rows: list[DatasetRow]) -> list[str]:
    """REQUIRED_FIELDS(label·category·source·collected_at)에 빈칸이 있는 행을 잡는다."""
    problems: list[str] = []
    for index, row in enumerate(rows, start=2):  # 1행은 헤더이므로 데이터는 2행부터
        empty = [name for name in REQUIRED_FIELDS if not getattr(row, name)]
        if empty:
            problems.append(f"필수칸 비움: dataset.csv {index}행 {empty} ({row.source})")
    return problems


def _check_sha256(readme_rows: list[ReadmeRow], raw_dir: Path) -> list[str]:
    """README의 SHA-256이 raw/ 파일 실제 다이제스트와 일치하는지 대조(Q5와 같은 계산)."""
    problems: list[str] = []
    for row in readme_rows:
        if not row.raw_file:
            problems.append(f"SHA-256: {row.source} raw 파일 기록 없음(수집 실패)")
            continue
        path = raw_dir / row.raw_file
        if not path.is_file():
            problems.append(f"SHA-256: {row.source} raw 파일 없음: {path}")
            continue
        actual = sha256_hex(path.read_bytes())
        if actual != row.sha256:
            problems.append(f"SHA-256: {row.source} 불일치 README {row.sha256} ≠ raw {actual}")
    return problems


if __name__ == "__main__":
    sys.exit(main())
