"""verify_domain_units.py — 2 도메인 단위 계산의 검증 조건 ①~⑥ 점검. 실행: `cd L1 && python3 -m tests.verify_domain_units`.

조건 하나에 점검 함수 하나(1번 verify_entry.py와 같은 꼴). ②③④⑥은 (fqdn, 기대 등록 단위, 기대 책임 경계, 기대 플랫폼 목록 일치) 비교라
_check_units 하나를 함께 쓴다. 파일을 만들지 않고 네트워크에 나가지 않는다. ①만 dataset.csv를 읽는다.
"""

import csv
import sys
from collections import Counter
from pathlib import Path

from src.domain_units import (
    HOST_DOMAIN,
    HOST_IPV4,
    HOST_IPV6,
    LIST_VERSION,
    MATCH_NONE,
    MATCH_NOT_APPLICABLE,
    MATCH_PSL_PRIVATE,
    MATCH_SUPPLEMENT,
    compute_domain_units,
)
from src.entry import extract_fqdn

__all__ = ["verify", "main"]

# 조건 ①이 읽는 0번 검증용 데이터셋. 이 파일(L1/tests/) → L1/ → 리포 루트로 올라가 고정한다.
DATASET_PATH: Path = Path(__file__).resolve().parents[2] / "data" / "verify_v1" / "dataset.csv"

# 조건 ②③④⑥ — (fqdn, 기대 등록 단위, 기대 책임 경계, 기대 플랫폼 목록 일치). 앞 둘은 명세 표, 넷째는 2026-08-26 설계자 실측값.
PSL_BUILDER_CASES: tuple[tuple[str, str, str, str], ...] = (
    ("foo.github.io", "github.io", "foo.github.io", MATCH_PSL_PRIVATE),
    ("a.b.blogspot.com", "blogspot.com", "b.blogspot.com", MATCH_PSL_PRIVATE),
)
SUPPLEMENT_CASES: tuple[tuple[str, str, str, str], ...] = (
    ("login-page.weebly.com", "weebly.com", "login-page.weebly.com", MATCH_SUPPLEMENT),
    ("abc.glitch.me", "glitch.me", "abc.glitch.me", MATCH_SUPPLEMENT),
)
PLAIN_CASES: tuple[tuple[str, str, str, str], ...] = (
    ("www.example.co.kr", "example.co.kr", "example.co.kr", MATCH_NONE),
    ("example.com", "example.com", "example.com", MATCH_NONE),
)
PUBLIC_SUFFIX_CASES: tuple[tuple[str, str, str, str], ...] = (
    (
        "p01--jpmorganchase--wx9l2zc8jjmz.code.run",
        "code.run",
        "p01--jpmorganchase--wx9l2zc8jjmz.code.run",
        MATCH_PSL_PRIVATE,
    ),
    ("github.io", "github.io", "github.io", MATCH_PSL_PRIVATE),
)

# 조건 ⑤ — 명세의 3건 (fqdn, 기대 호스트 종류).
IP_CASES: tuple[tuple[str, str], ...] = (
    ("203.0.113.5", HOST_IPV4),
    ("127.0.0.1", HOST_IPV4),
    ("[::1]", HOST_IPV6),
)


def verify() -> list[str]:
    """조건 ①~⑥을 순서대로 점검해 실패 메시지 목록을 돌려준다. 빈 리스트 = 전부 통과.

    메시지는 "①"~"⑥" 표시로 시작한다. main()이 이 표시로 조건별 통과/실패를 가려 찍는다.
    """
    problems: list[str] = []
    problems.extend(_check_dataset(DATASET_PATH))
    problems.extend(_check_psl_builders())
    problems.extend(_check_supplement_builders())
    problems.extend(_check_plain_domains())
    problems.extend(_check_ip_hosts())
    problems.extend(_check_public_suffix_hosts())
    return problems


def main() -> int:
    """단독 실행용: verify()를 돌려 조건별 통과/실패와 건수를 찍고, 전부 통과면 0, 아니면 1을 돌려준다."""
    print(f"[판] {LIST_VERSION}")
    problems = verify()
    conditions = (
        ("①", "실데이터 dataset.csv 600건 전부에서 값이 나옴"),
        ("②", f"PSL 웹빌더 {len(PSL_BUILDER_CASES)}건에서 두 값이 갈림"),
        ("③", f"보완 목록 {len(SUPPLEMENT_CASES)}건에서 두 값이 갈림"),
        ("④", f"보통 도메인 {len(PLAIN_CASES)}건에서 두 값이 같음"),
        ("⑤", f"IP 호스트 {len(IP_CASES)}건에서 목록을 타지 않음"),
        ("⑥", f"공개 접미사 호스트 {len(PUBLIC_SUFFIX_CASES)}건에서 이름 그대로"),
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
    """① dataset.csv의 url 600건을 extract_fqdn → compute_domain_units에 넣는다.

    통과: 값이 나온 건수 600, 도메인은 두 단위가 비지 않음, IP는 두 단위가 비고 MATCH_NOT_APPLICABLE.
    호스트 종류별·플랫폼 목록 일치별 건수는 조건이 아니라 정보로 찍는다(보완 목록이 값을 하는지 세는 용도).
    """
    problems: list[str] = []
    if not path.is_file():
        return [f"① dataset.csv 없음: {path}"]

    total = 0
    by_host_kind: Counter[str] = Counter()
    by_platform_match: Counter[str] = Counter()
    with path.open("r", encoding="utf-8", newline="") as fp:
        for index, record in enumerate(csv.DictReader(fp), start=2):  # 1행은 헤더
            url_raw = record.get("url", "") or ""
            try:
                units = compute_domain_units(extract_fqdn(url_raw))
            except Exception as exc:  # 값이 나와야 하는 자리에서 난 예외는 종류를 가리지 않고 실패다
                problems.append(f"① {index}행 예외 {type(exc).__name__}: {exc} ← {url_raw}")
                continue
            total += 1
            by_host_kind[units.host_kind] += 1
            by_platform_match[units.platform_match] += 1
            both_filled = bool(units.registrable_unit) and bool(units.responsibility_boundary)
            both_empty = units.registrable_unit == "" and units.responsibility_boundary == ""
            if units.host_kind == HOST_DOMAIN and not both_filled:
                problems.append(f"① {index}행 도메인인데 단위가 비었다: {units}")
            elif units.host_kind != HOST_DOMAIN and not (
                both_empty and units.platform_match == MATCH_NOT_APPLICABLE
            ):
                problems.append(f"① {index}행 IP인데 목록을 탔다: {units}")

    if total != 600:
        problems.insert(0, f"① 값이 나온 건수 {total} (기대 600)")
    print("[① 집계] 호스트 종류별: " + " · ".join(f"{k} {v}" for k, v in by_host_kind.items()))
    print("[① 집계] 플랫폼 목록 일치별: " + " · ".join(f"{k} {v}" for k, v in by_platform_match.items()))
    return problems


def _check_psl_builders() -> list[str]:
    """② PSL 사설 구역이 덮는 웹빌더 2건 — 등록 단위와 책임 경계가 명세대로 갈리는지."""
    return _check_units("②", PSL_BUILDER_CASES)


def _check_supplement_builders() -> list[str]:
    """③ 보완 목록이 덮는 것 2건 — 갈리지 않으면 보완 목록이 계산에 안 들어간 것이다."""
    return _check_units("③", SUPPLEMENT_CASES)


def _check_plain_domains() -> list[str]:
    """④ 보통 도메인 2건 — 두 값이 같은지."""
    return _check_units("④", PLAIN_CASES)


def _check_ip_hosts() -> list[str]:
    """⑤ IP 호스트 3건 — 호스트 종류가 기대값이고, 두 단위가 빈 문자열이고, 플랫폼 목록 일치가 MATCH_NOT_APPLICABLE인지."""
    problems: list[str] = []
    for fqdn, expected_kind in IP_CASES:
        try:
            units = compute_domain_units(fqdn)
        except Exception as exc:
            problems.append(f"⑤ {fqdn!r} → 예외 {type(exc).__name__}: {exc}")
            continue
        if (
            units.host_kind != expected_kind
            or units.registrable_unit != ""
            or units.responsibility_boundary != ""
            or units.platform_match != MATCH_NOT_APPLICABLE
        ):
            problems.append(f"⑤ {fqdn!r} → {units} (기대 종류 {expected_kind!r}, 두 단위 빔)")
    return problems


def _check_public_suffix_hosts() -> list[str]:
    """⑥ 호스트 이름 자체가 공개 접미사인 2건 — 그 이름이 그대로 단위로 나오는지."""
    return _check_units("⑥", PUBLIC_SUFFIX_CASES)


def _check_units(mark: str, cases: tuple[tuple[str, str, str, str], ...]) -> list[str]:
    """(fqdn, 기대 등록 단위, 기대 책임 경계, 기대 플랫폼 목록 일치)마다 compute_domain_units의 세 필드를 비교한다. 예외도 실패다."""
    problems: list[str] = []
    for fqdn, expected_registrable, expected_boundary, expected_match in cases:
        try:
            units = compute_domain_units(fqdn)
        except Exception as exc:
            problems.append(f"{mark} {fqdn!r} → 예외 {type(exc).__name__}: {exc}")
            continue
        actual = (units.registrable_unit, units.responsibility_boundary, units.platform_match)
        if actual != (expected_registrable, expected_boundary, expected_match):
            problems.append(
                f"{mark} {fqdn!r} → 등록 {actual[0]!r} · 책임 {actual[1]!r} · 일치 {actual[2]!r}"
                f" (기대 {expected_registrable!r} · {expected_boundary!r} · {expected_match!r})"
            )
    return problems


if __name__ == "__main__":
    sys.exit(main())
