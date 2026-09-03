"""verify_failure.py — 4 실패 처리 공통의 검증 조건 ①~⑥ 점검. 실행: `cd L1 && python3 -m tests.verify_failure`.

조건 하나에 점검 함수 하나(1~3번과 같은 꼴). ②가 만든 Timeout 기록 둘(DNS·HTTP)을 ③④⑤가 함께 쓴다.
네트워크에 나간다(example.com · generate_204 · 192.0.2.1). 파일을 쓰지 않는다. 실데이터는 돌리지 않는다.
handler가 아직 없어 Probes를 여기서 만들어 judge_timeout에 넘긴다.
"""

import sys
import time
from dataclasses import replace

import dns.resolver
import httpx

from src import failure
from src.common import (
    DNS_LIFETIME_S,
    DNS_TIMEOUT_S,
    INFRA_STATUS_RECEIVED,
    INFRA_STATUS_TIMEOUT,
    INFRA_STATUS_TOOL_ERROR,
    NAME_DNS_A,
    NAME_DNS_AAAA,
    NAME_DNS_NS,
    NAME_IP_ASN,
    NAME_RDAP,
    InfraRecord,
)
from src.failure import (
    DNS_PROBE_NAME,
    HTTP_PROBE_URL,
    PROBE_DNS,
    PROBE_HTTP,
    VERDICT_NOT_TIMEOUT,
    VERDICT_OUR_FAULT,
    VERDICT_TARGET_FAULT,
    Probes,
    judge_timeout,
    probe,
)
from src.infra.dns import not_queried_dns
from src.infra.rdap import not_queried_rdap

__all__ = ["verify", "main"]

# RFC 5737 문서용 대역 — 라우팅되지 않아 침묵한다(구조 답 2). 리졸버 주소와 HTTP 호스트 둘 다 이 주소.
SILENT_ADDRESS: str = "192.0.2.1"
SILENT_HTTP_URL: str = f"http://{SILENT_ADDRESS}/generate_204"


def verify() -> list[str]:
    """조건 ①~⑥을 순서대로 점검해 실패 메시지 목록을 돌려준다. 빈 리스트 = 전부 통과."""
    problems: list[str] = []
    problems.extend(_check_probes_answer())
    dns_record, http_record, made = _make_timeouts()
    problems.extend(made)
    problems.extend(_check_target_fault(dns_record, http_record))
    problems.extend(_check_our_fault(dns_record, http_record))
    problems.extend(_check_once(dns_record, http_record))
    problems.extend(_check_untouched())
    return problems


def main() -> int:
    """단독 실행용: verify()를 돌려 조건별 통과/실패를 찍고, 전부 통과면 0, 아니면 1을 돌려준다."""
    print(f"[설정] DNS_TIMEOUT_S={DNS_TIMEOUT_S} DNS_LIFETIME_S={DNS_LIFETIME_S} 침묵 주소={SILENT_ADDRESS}")
    started = time.perf_counter()
    problems = verify()
    conditions = (
        ("①", f"대조 대상이 답한다 ({DNS_PROBE_NAME} · {HTTP_PROBE_URL})"),
        ("②", f"Timeout을 만들 수 있다 ({SILENT_ADDRESS})"),
        ("③", "대상 탓 경로 — Timeout 기록 + 진짜 대조 → 계속"),
        ("④", "우리 탓 경로 — Timeout 기록 + 침묵하는 대조 → 실행 실패"),
        ("⑤", "한 종류에 한 번 — 같은 종류 Timeout 여럿에 대조 호출 1회"),
        ("⑥", "Timeout 아닌 기록은 건드리지 않음 — 대조 호출 0회"),
    )
    for mark, title in conditions:
        failures = [m for m in problems if m.startswith(mark)]
        print(f"[{mark} {title}] {'통과' if not failures else f'실패 {len(failures)}건'}")
        for message in failures:
            print(f"    {message}")
    print(f"[걸린 시간] {time.perf_counter() - started:.1f}초")
    if not problems:
        print("[검증] 전 항목 통과")
        return 0
    return 1


def _silent_resolver() -> dns.resolver.Resolver:
    """침묵하는 주소만 보는 리졸버. 조회·대조와 같은 시간 값이라 침묵이 같은 절차로 Timeout이 된다."""
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [SILENT_ADDRESS]
    resolver.timeout = DNS_TIMEOUT_S
    resolver.lifetime = DNS_LIFETIME_S
    return resolver


def _check_probes_answer() -> list[str]:
    """① example.com과 generate_204를 진짜로 물어 둘 다 「응답」인지. HTTP 상태 코드는 정보로 한 번 더 찍는다."""
    problems: list[str] = []
    for kind in (PROBE_DNS, PROBE_HTTP):
        started = time.perf_counter()
        answered = probe(kind, Probes())
        print(f"[① {kind}] {'응답' if answered else '무응답'} {time.perf_counter() - started:.3f}초")
        if not answered:
            problems.append(f"① {kind} 대조가 무응답")
    try:
        response = httpx.Client().get(HTTP_PROBE_URL)
        print(f"[① 정보] {HTTP_PROBE_URL} → HTTP {response.status_code}")
    except Exception as exc:
        print(f"[① 정보] {HTTP_PROBE_URL} → {type(exc).__name__}: {exc}")
    return problems


def _make_timeouts() -> tuple[InfraRecord, InfraRecord, list[str]]:
    """② 침묵하는 주소에 실제로 물어 status=Timeout 기록 둘(DNS A · RDAP)을 만든다. 예외 클래스·걸린 초가 실측값이다."""
    problems: list[str] = []

    started = time.perf_counter()
    try:
        _silent_resolver().resolve(DNS_PROBE_NAME, "A")
        dns_exc: BaseException | None = None
    except Exception as exc:
        dns_exc = exc
    dns_elapsed = time.perf_counter() - started
    print(f"[② DNS {SILENT_ADDRESS}] {type(dns_exc).__name__ if dns_exc else '응답'} {dns_elapsed:.3f}초: {dns_exc}")
    if not isinstance(dns_exc, dns.resolver.LifetimeTimeout):
        problems.append(f"② DNS {SILENT_ADDRESS} → {type(dns_exc).__name__ if dns_exc else '응답'} (기대 LifetimeTimeout)")

    started = time.perf_counter()
    try:
        httpx.Client().get(SILENT_HTTP_URL)
        http_exc: BaseException | None = None
    except Exception as exc:
        http_exc = exc
    http_elapsed = time.perf_counter() - started
    print(f"[② HTTP {SILENT_HTTP_URL}] {type(http_exc).__name__ if http_exc else '응답'} {http_elapsed:.3f}초: {http_exc}")
    if not isinstance(http_exc, httpx.TimeoutException):
        problems.append(f"② HTTP {SILENT_ADDRESS} → {type(http_exc).__name__ if http_exc else '응답'} (기대 TimeoutException)")

    # 3번 부품이 Timeout에 만드는 기록과 같은 모양(result 없음 · detail elapsed_s · reason 원문). 뒤 조건이 이 둘을 쓴다.
    dns_record = InfraRecord(NAME_DNS_A, INFRA_STATUS_TIMEOUT, None, {"elapsed_s": round(dns_elapsed, 3)}, str(dns_exc))
    http_record = InfraRecord(NAME_RDAP, INFRA_STATUS_TIMEOUT, None, {"elapsed_s": round(http_elapsed, 3)}, str(http_exc))
    return dns_record, http_record, problems


def _check_target_fault(dns_record: InfraRecord, http_record: InfraRecord) -> list[str]:
    """③ Timeout 기록 + 진짜 대조 → 「대상 탓, 계속」. Probes는 이 실행 몫으로 새로 하나."""
    problems: list[str] = []
    probes = Probes()
    for record in (dns_record, http_record):
        started = time.perf_counter()
        verdict = judge_timeout(record, probes)
        print(f"[③ {record.name}] {verdict} {time.perf_counter() - started:.3f}초")
        if verdict != VERDICT_TARGET_FAULT:
            problems.append(f"③ {record.name} → {verdict!r} (기대 {VERDICT_TARGET_FAULT!r})")
    return problems


def _check_our_fault(dns_record: InfraRecord, http_record: InfraRecord) -> list[str]:
    """④ Timeout 기록 + 대조도 침묵하는 주소로 돌림 → 「우리 탓, 실행 실패」."""
    problems: list[str] = []
    probes = Probes(resolver=_silent_resolver(), http_url=SILENT_HTTP_URL)
    for record in (dns_record, http_record):
        started = time.perf_counter()
        verdict = judge_timeout(record, probes)
        print(f"[④ {record.name}] {verdict} {time.perf_counter() - started:.3f}초")
        if verdict != VERDICT_OUR_FAULT:
            problems.append(f"④ {record.name} → {verdict!r} (기대 {VERDICT_OUR_FAULT!r})")
    return problems


def _check_once(dns_record: InfraRecord, http_record: InfraRecord) -> list[str]:
    """⑤ DNS 쪽 Timeout 넷(A·AAAA·NS·IP·ASN) + RDAP 하나를 한 Probes로 판별 → probe 호출 DNS 1 · HTTP 1."""
    problems: list[str] = []
    records = [replace(dns_record, name=name) for name in (NAME_DNS_A, NAME_DNS_AAAA, NAME_DNS_NS, NAME_IP_ASN)] + [http_record]
    probes = Probes()
    verdicts, calls = _judge_counting(records, probes)
    print(f"[⑤] 판별 {verdicts} / probe 호출 {calls} / answered {probes.answered}")
    if any(verdict != VERDICT_TARGET_FAULT for verdict in verdicts):
        problems.append(f"⑤ 판별 {verdicts} (기대 전부 {VERDICT_TARGET_FAULT!r})")
    if calls != {PROBE_DNS: 1, PROBE_HTTP: 1}:
        problems.append(f"⑤ probe 호출 {calls} (기대 {{{PROBE_DNS!r}: 1, {PROBE_HTTP!r}: 1}})")
    return problems


def _check_untouched() -> list[str]:
    """⑥ 응답 수신·Not Queried·도구 오류 기록 → 전부 「Timeout 아님」, probe 호출 0."""
    problems: list[str] = []
    records = [
        *not_queried_dns(),
        not_queried_rdap(),
        InfraRecord(NAME_DNS_A, INFRA_STATUS_RECEIVED, {"records": ["93.184.215.14"], "ttl": 60}, {"elapsed_s": 0.01}),
        InfraRecord(NAME_RDAP, INFRA_STATUS_TOOL_ERROR, None, {"elapsed_s": 0.01}, "검증용 도구 오류"),
    ]
    verdicts, calls = _judge_counting(records, Probes())
    print(f"[⑥] 판별 {verdicts} / probe 호출 {calls}")
    if any(verdict != VERDICT_NOT_TIMEOUT for verdict in verdicts):
        problems.append(f"⑥ 판별 {verdicts} (기대 전부 {VERDICT_NOT_TIMEOUT!r})")
    if calls:
        problems.append(f"⑥ probe 호출 {calls} (기대 0회)")
    return problems


def _judge_counting(records: list[InfraRecord], probes: Probes) -> tuple[list[str], dict[str, int]]:
    """failure.probe를 세는 함수로 잠시 바꿔 끼우고 기록들을 판별한다. judge_timeout이 probe를 모듈 이름으로 부르므로 통한다."""
    calls: dict[str, int] = {}
    original = failure.probe

    def counting(kind: str, probes_: Probes) -> bool:
        calls[kind] = calls.get(kind, 0) + 1
        return original(kind, probes_)

    failure.probe = counting
    try:
        verdicts = [judge_timeout(record, probes) for record in records]
    finally:
        failure.probe = original
    return verdicts, calls


if __name__ == "__main__":
    sys.exit(main())
