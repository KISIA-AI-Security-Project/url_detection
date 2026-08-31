"""verify_infra.py — 3 인프라 조회 3종의 검증 조건 ①~⑥ 점검. 실행: `cd L1 && python3 -m tests.verify_infra`.

조건 하나에 점검 함수 하나(1·2번과 같은 꼴). ①은 dataset.csv 표본 전부를 돌리고 그 결과를 ④(RDAP 404)·⑥이 함께 쓴다.
네트워크에 나간다(리졸버·Team Cymru·RDAP 서버). 파일을 쓰지 않는다. 대조 조회는 하지 않는다(5번 소관).
handler가 있지만 대조·예산 없이 부품만 600건 돌려 무변형을 비교하기 위해 _query_infra를 그대로 둔다(부품은 (기록, 원본) 쌍을 주고 여기서는 기록만 쓴다).
"""

import csv
import json
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path

from src.common import (
    INFRA_STATUS_NOT_QUERIED,
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
from src.domain_units import HOST_DOMAIN, DomainUnits, compute_domain_units
from src.entry import extract_fqdn
from src.infra.dns import not_queried_dns, query_dns
from src.infra.ip_asn import query_ip_asn
from src.infra.rdap import RDAP_TABLE_VERSION, not_queried_rdap, query_rdap

__all__ = ["verify", "main"]

# 조건 ①이 읽는 0번 검증용 데이터셋. 이 파일(L1/tests/) → L1/ → 리포 루트로 올라가 고정한다.
DATASET_PATH: Path = Path(__file__).resolve().parents[2] / "data" / "verify_v1" / "dataset.csv"
SAMPLE_LIMIT: int | None = None   # None = 표본 전부
URL_WORKERS: int = 8              # 동시에 도는 URL 수. URL 하나가 최대 4건(DNS 셋 + RDAP)을 낸다

# 조건 ② — 명세 값 그대로.
DOMAIN_CASE: str = "visionsfcunet.weebly.com"
DOMAIN_CASE_IPS: frozenset[str] = frozenset({"74.115.51.8", "74.115.51.9"})
DOMAIN_CASE_ASN: str = "27647"
DOMAIN_CASE_REGISTRABLE: str = "weebly.com"
# 조건 ③ — 명세 값 그대로.
IP_HOST_CASE: str = "162.241.69.15"
IP_HOST_CASE_ASN: str = "19871"
# 조건 ⑤ — 명세 값. 두 IP는 고정하지 않는다(앞단 IP는 바뀌고 조건은 「IP가 여럿이면 기록은 하나」).
MULTI_IP_CASE: str = "cqlhrj.com"
# 조건 ④ — RFC 6761이 .invalid를 「절대 해석되지 않는다」로 예약해 언제 돌려도 NXDOMAIN.
NXDOMAIN_CASE: str = "example.invalid"

RECORD_NAMES: tuple[str, ...] = (NAME_DNS_A, NAME_DNS_AAAA, NAME_DNS_NS, NAME_IP_ASN, NAME_RDAP)
STATUSES: tuple[str, ...] = (INFRA_STATUS_RECEIVED, INFRA_STATUS_TIMEOUT, INFRA_STATUS_NOT_QUERIED, INFRA_STATUS_TOOL_ERROR)
RDAP_KEYS: tuple[str, ...] = ("registration", "expiration", "last_changed", "status", "nameservers", "registrar")


def verify() -> list[str]:
    """조건 ①~⑥을 순서대로 점검해 실패 메시지 목록을 돌려준다. 빈 리스트 = 전부 통과."""
    problems: list[str] = []
    results = _run_dataset(DATASET_PATH)
    problems.extend(_check_five_records(results))
    problems.extend(_check_domain_host())
    problems.extend(_check_ip_host())
    problems.extend(_check_negative_answers(results))
    problems.extend(_check_multi_ip())
    problems.extend(_check_timeout_continues(results))
    return problems


def main() -> int:
    """단독 실행용: verify()를 돌려 조건별 통과/실패와 건수를 찍고, 전부 통과면 0, 아니면 1을 돌려준다."""
    print(f"[판] {RDAP_TABLE_VERSION}")
    print(f"[설정] SAMPLE_LIMIT={SAMPLE_LIMIT} URL_WORKERS={URL_WORKERS}")
    started = time.perf_counter()
    problems = verify()
    conditions = (
        ("①", "실데이터 표본 전부에서 기록 다섯·status 어휘 넷"),
        ("②", f"도메인 호스트 {DOMAIN_CASE}에서 세 조회가 값을 줌"),
        ("③", f"IP 호스트 {IP_HOST_CASE}에서 IP·ASN만 응답"),
        ("④", "부정 응답을 번역하지 않음(NXDOMAIN · RDAP 404)"),
        ("⑤", f"IP 여럿 {MULTI_IP_CASE}에서 IP·ASN 기록 하나"),
        ("⑥", "Timeout이 나도 나머지 기록이 만들어짐"),
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


def _query_infra(fqdn: str, units: DomainUnits) -> list[InfraRecord]:
    """handler 대역 — 구조 (c) 본체 2~7. 반환 순서는 A·AAAA·NS·IP·ASN·RDAP."""
    if units.host_kind != HOST_DOMAIN:
        bare = fqdn[1:-1] if fqdn.startswith("[") and fqdn.endswith("]") else fqdn   # Cymru 질의 이름은 대괄호를 모른다
        return [*not_queried_dns(), query_ip_asn((bare,))[0], not_queried_rdap()]
    with ThreadPoolExecutor(max_workers=4) as pool:
        dns_futures = [pool.submit(query_dns, fqdn, record_type) for record_type in ("A", "AAAA", "NS")]
        rdap_future = pool.submit(query_rdap, units.registrable_unit)
        dns_records = [future.result()[0] for future in dns_futures]
        ip_asn_record, _ = query_ip_asn(_collect_ips(dns_records))   # RDAP이 아직 도는 동안 시작한다
        rdap_record, _ = rdap_future.result()
    return [*dns_records, ip_asn_record, rdap_record]


def _collect_ips(dns_records: list[InfraRecord]) -> tuple[str, ...]:
    """A·AAAA 기록의 records에서 IP를 처음 나온 순서로 모으고 중복을 뺀다. result가 dict가 아닌 기록(NXDOMAIN 등)은 건너뛴다."""
    ips: list[str] = []
    for record in dns_records:
        if record.name in (NAME_DNS_A, NAME_DNS_AAAA) and isinstance(record.result, dict):
            for ip in record.result.get("records", []):
                if ip not in ips:
                    ips.append(ip)
    return tuple(ips)


def _run_dataset(path: Path) -> list[tuple[str, list[InfraRecord]]]:
    """표본 전부를 URL_WORKERS개씩 동시에 돌려 (url, 기록 다섯)을 모은다. 예외가 난 URL은 기록 없이 둔다."""
    if not path.is_file():
        print(f"[① 준비] dataset.csv 없음: {path}")
        return []
    with path.open("r", encoding="utf-8", newline="") as fp:
        urls = [record.get("url", "") or "" for record in csv.DictReader(fp)]
    if SAMPLE_LIMIT is not None:
        urls = urls[:SAMPLE_LIMIT]
    print(f"[① 준비] 표본 {len(urls)}건, URL 동시 {URL_WORKERS}")
    done = 0
    results: list[tuple[str, list[InfraRecord]]] = []
    with ThreadPoolExecutor(max_workers=URL_WORKERS) as pool:
        for url, records in pool.map(_run_one, urls):
            results.append((url, records))
            done += 1
            if done % 100 == 0:
                print(f"[① 진행] {done}/{len(urls)}")
    return results


def _run_one(url_raw: str) -> tuple[str, list[InfraRecord]]:
    try:
        fqdn = extract_fqdn(url_raw)
        return url_raw, _query_infra(fqdn, compute_domain_units(fqdn))
    except Exception as exc:   # 부품은 예외를 내지 않기로 했으므로 여기 걸리면 그 자체가 ①의 실패다
        print(f"[예외] {type(exc).__name__}: {exc} ← {url_raw}")
        return url_raw, []


def _check_five_records(results: list[tuple[str, list[InfraRecord]]]) -> list[str]:
    """① URL마다 기록이 정확히 다섯(이름 순서 그대로)이고 status가 어휘 넷 중 하나인지. name×status 건수표를 정보로 찍는다."""
    problems: list[str] = []
    expected_total = 600 if SAMPLE_LIMIT is None else min(SAMPLE_LIMIT, 600)
    if len(results) != expected_total:
        problems.append(f"① 표본 건수 {len(results)} (기대 {expected_total})")
    table: Counter[tuple[str, str]] = Counter()
    not_received: list[str] = []
    for url, records in results:
        names = tuple(record.name for record in records)
        if names != RECORD_NAMES:
            problems.append(f"① 기록 다섯이 아님 {names} ← {url}")
        for record in records:
            table[(record.name, record.status)] += 1
            if record.status not in STATUSES:
                problems.append(f"① status 어휘 밖 {record.status!r} ({record.name}) ← {url}")
            if record.status in (INFRA_STATUS_TIMEOUT, INFRA_STATUS_TOOL_ERROR):
                not_received.append(f"{record.name} {record.status} {record.detail} {record.reason} ← {url}")
    print("[① 집계] name × status:")
    for name in RECORD_NAMES:
        cells = " · ".join(f"{status} {table[(name, status)]}" for status in STATUSES if table[(name, status)])
        print(f"    {name:9s} {cells}")
    print(f"[① 집계] Timeout·도구 오류 기록 {len(not_received)}건:")
    for line in not_received:
        print(f"    {line}")
    return problems


def _check_domain_host() -> list[str]:
    """② 도메인 호스트에서 A·IP·ASN·RDAP 세 조회가 명세의 값을 주는지."""
    units = compute_domain_units(DOMAIN_CASE)
    records = _query_infra(DOMAIN_CASE, units)
    _print_records("②", DOMAIN_CASE, records)
    problems: list[str] = []
    by_name = {record.name: record for record in records}
    a_record = by_name.get(NAME_DNS_A)
    if a_record is None or not isinstance(a_record.result, dict):
        problems.append(f"② A 기록이 값이 아님: {a_record}")
    else:
        if set(a_record.result.get("records", [])) != DOMAIN_CASE_IPS:
            problems.append(f"② A records {a_record.result.get('records')} (기대 {sorted(DOMAIN_CASE_IPS)})")
        if not (0 < a_record.result.get("ttl", 0) <= 3600):
            problems.append(f"② A ttl {a_record.result.get('ttl')} (기대 0 < ttl <= 3600)")
    asn_record = by_name.get(NAME_IP_ASN)
    if asn_record is None or not isinstance(asn_record.result, dict):
        problems.append(f"② IP·ASN 기록이 값이 아님: {asn_record}")
    else:
        bundles = asn_record.result
        if len(bundles) != len(DOMAIN_CASE_IPS) or any(
            not isinstance(b, dict) or b.get("asn") != DOMAIN_CASE_ASN for b in bundles.values()
        ):
            problems.append(f"② IP·ASN 묶음 {bundles} (기대 IP {len(DOMAIN_CASE_IPS)}개 전부 asn {DOMAIN_CASE_ASN})")
    if units.registrable_unit != DOMAIN_CASE_REGISTRABLE:
        problems.append(f"② 등록 단위 {units.registrable_unit!r} (기대 {DOMAIN_CASE_REGISTRABLE!r})")
    rdap_record = by_name.get(NAME_RDAP)
    if rdap_record is None or not isinstance(rdap_record.result, dict):
        problems.append(f"② RDAP 기록이 값이 아님: {rdap_record}")
    else:
        missing = [key for key in RDAP_KEYS if key not in rdap_record.result]
        if missing:
            problems.append(f"② RDAP 조각 빠짐 {missing}")
    return problems


def _check_ip_host() -> list[str]:
    """③ IP 호스트에서 IP·ASN만 응답하고 나머지 넷은 Not Queried + reason, 기록은 다섯인지."""
    units = compute_domain_units(IP_HOST_CASE)
    records = _query_infra(IP_HOST_CASE, units)
    _print_records("③", IP_HOST_CASE, records)
    problems: list[str] = []
    if tuple(record.name for record in records) != RECORD_NAMES:
        problems.append(f"③ 기록 다섯이 아님: {[record.name for record in records]}")
    for record in records:
        if record.name == NAME_IP_ASN:
            bundle = record.result.get(IP_HOST_CASE) if isinstance(record.result, dict) else None
            if record.status != INFRA_STATUS_RECEIVED or not isinstance(bundle, dict) or bundle.get("asn") != IP_HOST_CASE_ASN:
                problems.append(f"③ IP·ASN {record.status} {record.result} (기대 응답 수신, asn {IP_HOST_CASE_ASN})")
        elif record.status != INFRA_STATUS_NOT_QUERIED or not record.reason:
            problems.append(f"③ {record.name} status {record.status!r} reason {record.reason!r} (기대 Not Queried + reason)")
    return problems


def _check_negative_answers(results: list[tuple[str, list[InfraRecord]]]) -> list[str]:
    """④ NXDOMAIN은 응답 수신 + result NXDOMAIN, RDAP 404는 응답 수신 + {registered: false}. 404 대상은 ① 결과에서 첫 것."""
    problems: list[str] = []
    record, _ = query_dns(NXDOMAIN_CASE, "A")
    print(f"[④ {NXDOMAIN_CASE}] {_dump(record)}")
    if record.status != INFRA_STATUS_RECEIVED or record.result != "NXDOMAIN":
        problems.append(f"④ {NXDOMAIN_CASE} → {record.status} {record.result!r} (기대 응답 수신 NXDOMAIN)")
    for url, records in results:
        rdap = next((r for r in records if r.name == NAME_RDAP), None)
        if rdap is not None and rdap.result == {"registered": False}:
            print(f"[④ RDAP 404 ← {url}] {_dump(rdap)}")
            if rdap.status != INFRA_STATUS_RECEIVED:
                problems.append(f"④ RDAP 404인데 status {rdap.status!r} ← {url}")
            break
    else:
        problems.append("④ RDAP 404 대상 없음 — ① 결과에 registered:false 기록이 없다")
    return problems


def _check_multi_ip() -> list[str]:
    """⑤ A가 여럿인 도메인에서 IP·ASN 기록은 하나이고 그 안의 묶음이 IP 개수만큼인지."""
    units = compute_domain_units(MULTI_IP_CASE)
    records = _query_infra(MULTI_IP_CASE, units)
    _print_records("⑤", MULTI_IP_CASE, records)
    problems: list[str] = []
    ips = _collect_ips(records)
    if len(ips) < 2:
        problems.append(f"⑤ IP가 여럿이 아님 {ips} — 대상을 갈아 끼울 것")
    asn_records = [record for record in records if record.name == NAME_IP_ASN]
    if len(asn_records) != 1:
        problems.append(f"⑤ IP·ASN 기록 {len(asn_records)}개 (기대 1)")
    elif asn_records[0].status != INFRA_STATUS_RECEIVED or not isinstance(asn_records[0].result, dict):
        problems.append(f"⑤ IP·ASN {asn_records[0].status} {asn_records[0].result}")
    elif set(asn_records[0].result) != set(ips):
        problems.append(f"⑤ 묶음의 IP {sorted(asn_records[0].result)} ≠ DNS의 IP {sorted(ips)}")
    return problems


def _check_timeout_continues(results: list[tuple[str, list[InfraRecord]]]) -> list[str]:
    """⑥ ① 결과에서 DNS Timeout이 난 URL 하나를 골라 기록 다섯이 status를 채운 채 다 있는지. 대상 없으면 미검증으로 통과."""
    for url, records in results:
        if any(r.name in (NAME_DNS_A, NAME_DNS_AAAA, NAME_DNS_NS) and r.status == INFRA_STATUS_TIMEOUT for r in records):
            _print_records("⑥", url, records)
            problems: list[str] = []
            if tuple(record.name for record in records) != RECORD_NAMES:
                problems.append(f"⑥ 기록 다섯이 아님 {[record.name for record in records]} ← {url}")
            if any(record.status not in STATUSES for record in records):
                problems.append(f"⑥ status 빈 기록 있음 ← {url}")
            return problems
    print("[⑥] 대상 없음 — 표본에 DNS Timeout이 0건이라 미검증(통과)")
    return []


def _print_records(mark: str, target: str, records: list[InfraRecord]) -> None:
    print(f"[{mark} {target}] 기록 {len(records)}개:")
    for record in records:
        print(f"    {_dump(record)}")


def _dump(record: InfraRecord) -> str:
    return json.dumps(asdict(record), ensure_ascii=False)


if __name__ == "__main__":
    sys.exit(main())
