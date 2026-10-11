"""verify_entry.py — 1 입구 처리의 검증 조건 ①~④ 점검. 실행: `cd L1 && python -m tests.verify_entry`.

조건 하나에 점검 함수 하나. 실패해도 파일은 만들지 않고 보고만 한다(0번 verify_dataset.py와 같은 꼴).
① dataset.csv 600건 전부 파싱 · ② 회피 기법 9건의 fqdn 값 · ③ 못 읽는 입력 9건에서 파서의 예외 ·
④ 호스트 없는 스킴 4건에서 EmptyHostError. 네트워크에 나가지 않는다.
"""

import csv
import sys
from pathlib import Path

from src.entry import EmptyHostError, extract_fqdn

__all__ = ["verify", "main"]

# 조건 ①이 읽는 0번 검증용 데이터셋. 이 파일(L1/tests/) → L1/ → 리포 루트로 올라가 고정한다.
DATASET_PATH: Path = Path(__file__).resolve().parents[2] / "data" / "verify_v1" / "dataset.csv"

# 조건 ② — 명세 표 9쌍 그대로 (입력, 기대 fqdn). 일곱째 항목의 "\t"가 명세의 [탭 문자]다.
EVASION_CASES: tuple[tuple[str, str], ...] = (
    ("http://example.com\\evil.com/", "example.com"),
    ("http://user@evil.com@good.com/", "good.com"),
    ("http://0x7f.0x0.0x0.0x1/", "127.0.0.1"),
    ("http://2130706433/", "127.0.0.1"),
    ("http://EXAMPLE.COM/Path", "example.com"),
    ("http://日本.jp/", "xn--wgv71a.jp"),
    ("http://exa\tmple.com/", "example.com"),
    ("http://example.com:80/", "example.com"),
    ("https://example.com./", "example.com."),
)

# 조건 ③ — 명세의 9건 그대로. 파서가 거부해야 하는 입력.
REJECT_CASES: tuple[str, ...] = (
    "http://",
    "http://exa mple.com/",
    "http://[::1/",
    "http://999.999.999.999/",
    "http://1.2.3.4.5/",
    "http://exa<mple.com/",
    "http://%zz.com/",
    "http://example.com:abc/",
    "http://example.com:99999/",
)

# 조건 ④ — 명세의 4건. 파싱은 되지만 호스트가 빈 문자열인 입력.
# data:의 본문은 임의로 정했다 — 어떤 본문이든 data: 스킴의 호스트는 빈 문자열이다.
HOSTLESS_CASES: tuple[str, ...] = (
    "mailto:user@example.com",
    "javascript:alert(1)",
    "data:text/html,<h1>hi</h1>",
    "file:///etc/passwd",
)


def verify() -> list[str]:
    """조건 ①~④를 순서대로 점검해 실패 메시지 목록을 돌려준다. 빈 리스트 = 전부 통과.

    메시지는 "①"~"④" 표시로 시작한다. main()이 이 표시로 조건별 통과/실패를 가려 찍는다.
    값으로 돌려주는 이유: 찍는 일과 종료 코드 정하는 일을 main() 한 곳에 모으기 위함.
    """
    problems: list[str] = []
    problems.extend(_check_dataset(DATASET_PATH))
    problems.extend(_check_evasions())
    problems.extend(_check_rejects())
    problems.extend(_check_hostless())
    return problems


def main() -> int:
    """단독 실행용: verify()를 돌려 조건별 통과/실패와 건수를 찍고, 전부 통과면 0, 아니면 1을 돌려준다."""
    problems = verify()
    # 조건 표시(①~④)와 그 조건이 검사한 건수. ①의 600은 명세가 정한 dataset.csv 건수다.
    conditions = (
        ("①", "실데이터 dataset.csv 600건 전부 파싱"),
        ("②", f"회피 기법 {len(EVASION_CASES)}건의 fqdn 값"),
        ("③", f"못 읽는 입력 {len(REJECT_CASES)}건에서 파서 예외"),
        ("④", f"호스트 없는 스킴 {len(HOSTLESS_CASES)}건에서 EmptyHostError"),
    )
    for mark, title in conditions:
        failures = [m for m in problems if m.startswith(mark)]
        print(f"[{mark} {title}] {'통과' if not failures else f'실패 {len(failures)}건'}")
        for message in failures:
            print(f"    {message}")
    if not problems:
        print("[검증] 전 항목 통과")
        return 0
    return 1


def _check_dataset(path: Path) -> list[str]:
    """① dataset.csv의 url 칸을 한 건씩 extract_fqdn에 넣어 성공·예외·빈 호스트 건수를 센다.

    기대는 성공 600 · 예외 0 · 빈 호스트 0. 예외를 여기서 잡는 것은 입구 처리가 아니라
    부른 쪽(이 스크립트)이 세기 위해서다 — 입구 처리 안에서는 잡지 않는다.
    """
    problems: list[str] = []
    if not path.is_file():
        return [f"① dataset.csv 없음: {path}"]

    ok = 0
    empty_host = 0
    other_error = 0
    # url 칸은 원문 그대로 넣는다(0번이 변형 없이 저장한 값). newline=""은 csv 모듈의 표준 요구.
    with path.open("r", encoding="utf-8", newline="") as fp:
        for index, record in enumerate(csv.DictReader(fp), start=2):  # 1행은 헤더
            url_raw = record.get("url", "") or ""
            try:
                extract_fqdn(url_raw)
                ok += 1
            except EmptyHostError as exc:
                empty_host += 1
                problems.append(f"① {index}행 빈 호스트: {exc}")
            except Exception as exc:  # 파서의 거부 등 그 외 전부 — 기대가 0건이라 종류를 가르지 않는다
                other_error += 1
                problems.append(f"① {index}행 예외 {type(exc).__name__}: {exc} ← {url_raw}")

    if (ok, other_error, empty_host) != (600, 0, 0):
        problems.insert(
            0, f"① 집계 성공 {ok} · 예외 {other_error} · 빈 호스트 {empty_host} (기대 600·0·0)"
        )
    return problems


def _check_evasions() -> list[str]:
    """② 회피 기법 9건 — 입력마다 extract_fqdn의 반환값이 명세의 기대 fqdn과 같은지 비교한다."""
    problems: list[str] = []
    for url_raw, expected in EVASION_CASES:
        try:
            actual = extract_fqdn(url_raw)
        except Exception as exc:  # 값이 나와야 하는 자리에서 예외가 나면 그것도 실패다
            problems.append(f"② {url_raw!r} → 예외 {type(exc).__name__}: {exc} (기대 {expected!r})")
            continue
        if actual != expected:
            problems.append(f"② {url_raw!r} → {actual!r} (기대 {expected!r})")
    return problems


def _check_rejects() -> list[str]:
    """③ 못 읽는 입력 9건 — 각각에서 예외가 부른 쪽에 보여야 하고, 그 예외는 EmptyHostError가 아니어야 한다.

    EmptyHostError가 아니어야 하는 이유: ③은 파서가 거부하는 경로이고 ④는 입구 처리가 거부하는
    경로다. 예외형으로 갈라 두 경로가 실제로 다른지 확인한다.
    """
    problems: list[str] = []
    for url_raw in REJECT_CASES:
        try:
            actual = extract_fqdn(url_raw)
        except EmptyHostError as exc:
            problems.append(f"③ {url_raw!r} → 파서 거부가 아니라 EmptyHostError: {exc}")
        except Exception:
            continue  # 파서의 예외가 부른 쪽까지 올라왔다 — 통과
        else:
            problems.append(f"③ {url_raw!r} → 예외 없이 {actual!r} 반환")
    return problems


def _check_hostless() -> list[str]:
    """④ 호스트 없는 스킴 4건 — 각각에서 EmptyHostError가 부른 쪽에 보여야 한다."""
    problems: list[str] = []
    for url_raw in HOSTLESS_CASES:
        try:
            actual = extract_fqdn(url_raw)
        except EmptyHostError:
            continue  # 입구 처리가 직접 던진 예외가 부른 쪽까지 올라왔다 — 통과
        except Exception as exc:
            problems.append(f"④ {url_raw!r} → EmptyHostError가 아닌 {type(exc).__name__}: {exc}")
        else:
            problems.append(f"④ {url_raw!r} → 예외 없이 {actual!r} 반환")
    return problems


if __name__ == "__main__":
    sys.exit(main())
