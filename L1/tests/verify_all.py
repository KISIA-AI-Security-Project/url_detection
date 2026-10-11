"""verify_all.py — 1~5번 검증을 구현 순서대로 한 번에 돌린다. 실행: `cd L1 && python3 -m tests.verify_all`.

「검증끼리 import 금지」의 유일한 예외 — 이 파일은 헬퍼를 나눠 쓰지 않고 각 검증의 main()을 부르기만 하는 조립이다
(handler가 부품을 모으는 것과 같은 선). 기존 검증 다섯 파일은 고치지 않는다.
검증 하나가 실패해도 멈추지 않고 나머지를 마저 돌린 뒤, 전부 통과일 때만 0을 돌려준다. 파일은 각 검증이 스스로 만드는 것 외에 만들지 않는다.
"""

import sys
import time
from collections.abc import Callable

from tests import verify_domain_units, verify_entry, verify_failure, verify_infra, verify_records

__all__ = ["verify", "main"]

# 실행 순서 = 구현 순서(1 입구 → 2 도메인 단위 → 3 인프라 조회 → 4 실패 처리 → 5 기록·출구).
# 앞 칸은 출력 줄의 표지, 뒤 칸은 그 검증의 main(0 = 전부 통과, 1 = 실패 있음).
_VERIFIERS: tuple[tuple[str, Callable[[], int]], ...] = (
    ("entry", verify_entry.main),
    ("domain_units", verify_domain_units.main),
    ("infra", verify_infra.main),
    ("failure", verify_failure.main),
    ("records", verify_records.main),
)

# 검증 하나의 결과 — (이름, 통과 여부, 걸린 초, 실패 사유). 사유는 main이 1을 돌려줬으면 "실패", 예외로 죽었으면 그 예외의 이름과 메시지.
Result = tuple[str, bool, float, str]


def verify() -> list[Result]:
    """다섯 검증을 순서대로 돌려 결과를 모은다. main이 0이 아니거나 예외로 죽어도 다음 검증으로 간다 — 예외를 삼키는 것이 아니라 사유 칸에 적어 남긴다."""
    results: list[Result] = []
    for name, run_main in _VERIFIERS:
        print(f"===== [{name}] 시작 =====")
        started = time.perf_counter()
        try:
            code = run_main()
            passed, reason = code == 0, "" if code == 0 else "실패"
        except Exception as exc:   # 검증 자체가 죽은 것도 실패다 — 멈추지 않고 나머지를 돌리기 위해 여기서 받는다
            passed, reason = False, f"{type(exc).__name__}: {exc}"
        results.append((name, passed, time.perf_counter() - started, reason))
    return results


def main() -> int:
    """단독 실행용: verify()를 돌려 검증마다 한 줄, 마지막에 합계 한 줄을 찍고, 전부 통과면 0, 아니면 1을 돌려준다."""
    started = time.perf_counter()
    results = verify()
    print("===== [합계] =====")
    for name, passed, elapsed, reason in results:
        print(f"[{name}] {'통과' if passed else f'실패 ({reason})'} · {elapsed:.1f}초")
    passed_count = sum(1 for _name, passed, _elapsed, _reason in results if passed)
    print(f"[합계] {len(results)}개 중 통과 {passed_count} · 실패 {len(results) - passed_count} · {time.perf_counter() - started:.1f}초")
    return 0 if passed_count == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
