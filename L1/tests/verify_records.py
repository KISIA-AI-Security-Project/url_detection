"""verify_records.py — 5 기록·출구의 검증 조건 ①~⑤ 점검. 실행: `cd L1 && python3 -m tests.verify_records`.

조건 하나에 점검 함수 하나(1~4번과 같은 꼴). ①이 실제로 돌린 실행 다섯의 출구·원본을 ③·④·⑤가 함께 쓴다.
처음으로 실행 한 번 전체(handler.run)를 돈다. 네트워크에 나간다(①·④ 실데이터, ② 침묵 주소 대조).
파일을 쓴다 — L1/tests/out/ 아래. 시작 때 비우고 끝나면 남긴다(설계자가 열어본다).
본체에 검증용 인자는 없다 — 대조 대상·예산·조회 함수는 handler 모듈의 이름을 잠시 갈아 끼우고 finally로 되돌린다(4번 검증과 같은 방식).
"""

import csv
import json
import shutil
import sys
import threading
import time
from pathlib import Path

import dns.resolver

from src import handler
from src.common import (
    DNS_LIFETIME_S,
    DNS_TIMEOUT_S,
    FAILURE_BUDGET_EXCEEDED,
    FAILURE_PROBE_SILENT,
    INFRA_STATUS_NOT_QUERIED,
    INFRA_STATUS_RECEIVED,
    INFRA_STATUS_TIMEOUT,
    NAME_DNS_A,
    NAME_DNS_AAAA,
    NAME_DNS_NS,
    NAME_IP_ASN,
    NAME_RDAP,
    OVERALL_COMPLETED,
    OVERALL_FAILED,
    InfraRecord,
)
from src.domain_units import HOST_DOMAIN, compute_domain_units
from src.entry import extract_fqdn
from src.failure import Probes
from src.records import (
    KEY_ATTEMPT_ID,
    KEY_DOMAIN_UNITS,
    KEY_FAILURE_REASON,
    KEY_INFRA_RECORDS,
    KEY_JOB_ID,
    KEY_OVERALL,
    RAW_FILE_BY_NAME,
    UNIT_KEYS,
    output_key,
    raw_key,
    save,
)

__all__ = ["verify", "main"]

DATASET_PATH: Path = Path(__file__).resolve().parents[2] / "data" / "verify_v1" / "dataset.csv"
OUT_ROOT: Path = Path(__file__).with_name("out")   # 출구·원본이 남는 자리. 시작 때 비운다
JOB_ID: str = "verify-records"
DOMAIN_SAMPLES: int = 3   # ① 도메인 호스트 건수 — 앞 6행이 IP 4·도메인 2라 앞 N행 그대로는 도메인 경로가 얇다
IP_SAMPLES: int = 2       # ① IP 호스트 건수

# ② — RFC 5737 문서용 대역, 라우팅되지 않아 침묵한다. 4번 검증과 같은 장치인데 검증끼리 import하지 않아 여기 다시 둔다.
SILENT_ADDRESS: str = "192.0.2.1"
SILENT_HTTP_URL: str = f"http://{SILENT_ADDRESS}/generate_204"
SLOW_S: float = 20.0          # ② RDAP 대역이 자는 시간. DNS 대조 15초보다 길어야 「기다리지 않았다」가 보인다
TINY_BUDGET_S: float = 0.001  # ④ 예산

RECORD_NAMES: tuple[str, ...] = (NAME_DNS_A, NAME_DNS_AAAA, NAME_DNS_NS, NAME_IP_ASN, NAME_RDAP)
OUTPUT_KEYS: frozenset[str] = frozenset({KEY_JOB_ID, KEY_ATTEMPT_ID, KEY_DOMAIN_UNITS, KEY_INFRA_RECORDS, KEY_OVERALL})
_NAME_BY_TYPE: dict[str, str] = {"A": NAME_DNS_A, "AAAA": NAME_DNS_AAAA, "NS": NAME_DNS_NS}

# ①의 실행 하나 — (url, attempt_id, 출구, 원본, 걸린 초)
Run = tuple[str, str, dict, dict[str, dict[str, str]], float]


def verify() -> list[str]:
    """조건 ①~⑤를 순서대로 점검해 실패 메시지 목록을 돌려준다. 빈 리스트 = 전부 통과."""
    _reset_out()
    problems: list[str] = []
    runs, made = _run_samples()
    problems.extend(made)
    problems.extend(_check_completed(runs))
    problems.extend(_check_our_fault())
    problems.extend(_check_unwritable(runs))
    problems.extend(_check_budget(runs))
    problems.extend(_check_raw(runs))
    return problems


def main() -> int:
    """단독 실행용: verify()를 돌려 조건별 통과/실패를 찍고, 전부 통과면 0, 아니면 1을 돌려준다."""
    print(f"[설정] 예산 {handler.TIME_BUDGET_S}초 · 표본 도메인 {DOMAIN_SAMPLES} + IP {IP_SAMPLES} · 침묵 주소 {SILENT_ADDRESS} · 출력 {OUT_ROOT}")
    started = time.perf_counter()
    problems = verify()
    conditions = (
        ("①", f"완료 경로 — 검증셋 URL {DOMAIN_SAMPLES + IP_SAMPLES}건의 출구가 정본 1.3 모양"),
        ("②", "우리 탓 경로 — 대조 침묵 → 전체상태 실패, 남은 조회를 기다리지 않음"),
        ("③", "출구 미성립 — 쓸 수 없는 저장 경로 → 예외, 파일 없음"),
        ("④", f"예산 초과 — 예산 {TINY_BUDGET_S}초 → 전체상태 실패"),
        ("⑤", "원본 저장 — 완료 경로의 raw 파일"),
    )
    for mark, title in conditions:
        failures = [m for m in problems if m.startswith(mark)]
        print(f"[{mark} {title}] {'통과' if not failures else f'실패 {len(failures)}건'}")
        for message in failures:
            print(f"    {message}")
    print(f"[걸린 시간] {time.perf_counter() - started:.1f}초 (버려진 조회 스레드가 남아 프로세스 종료는 이보다 늦을 수 있다)")
    if not problems:
        print("[검증] 전 항목 통과")
        return 0
    return 1


def _reset_out() -> None:
    shutil.rmtree(OUT_ROOT, ignore_errors=True)
    OUT_ROOT.mkdir()


def _silent_resolver() -> dns.resolver.Resolver:
    """침묵하는 주소만 보는 리졸버. 조회·대조와 같은 시간 값이라 침묵이 같은 절차로 Timeout이 된다."""
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [SILENT_ADDRESS]
    resolver.timeout = DNS_TIMEOUT_S
    resolver.lifetime = DNS_LIFETIME_S
    return resolver


def _pick_urls() -> list[str]:
    """dataset.csv 앞에서부터 도메인 호스트 DOMAIN_SAMPLES건 + IP 호스트 IP_SAMPLES건. 호스트 종류는 2번 부품으로 가른다."""
    domain_urls: list[str] = []
    ip_urls: list[str] = []
    with DATASET_PATH.open("r", encoding="utf-8", newline="") as fp:
        for row in csv.DictReader(fp):
            url = row.get("url", "") or ""
            is_domain = compute_domain_units(extract_fqdn(url)).host_kind == HOST_DOMAIN
            if is_domain and len(domain_urls) < DOMAIN_SAMPLES:
                domain_urls.append(url)
            elif not is_domain and len(ip_urls) < IP_SAMPLES:
                ip_urls.append(url)
            if len(domain_urls) == DOMAIN_SAMPLES and len(ip_urls) == IP_SAMPLES:
                break
    return domain_urls + ip_urls


def _run_samples() -> tuple[list[Run], list[str]]:
    """① 고른 URL마다 run → 로컬 save. 걸린 초·파일 경로·크기·기록 status를 찍는다. 예외가 난 건은 ①의 실패로 적고 계속한다."""
    problems: list[str] = []
    runs: list[Run] = []
    for index, url in enumerate(_pick_urls(), start=1):
        attempt_id = f"{index:02d}"
        started = time.perf_counter()
        try:
            output, raws = handler.run(url, JOB_ID, attempt_id)
            save(output, raws, JOB_ID, attempt_id, OUT_ROOT)
        except Exception as exc:   # 본체는 예외를 밖으로 내는 게 정책이지만 실데이터 완료 경로에서 나면 그 자체가 ①의 실패다
            problems.append(f"① {type(exc).__name__}: {exc} ← {url}")
            continue
        elapsed = time.perf_counter() - started
        path = OUT_ROOT / output_key(JOB_ID, attempt_id)
        statuses = " · ".join(f"{r['name']} {r['status']}" for r in output[KEY_INFRA_RECORDS])
        print(f"[① {attempt_id}] {elapsed:.1f}초 {output[KEY_OVERALL]} {path.relative_to(OUT_ROOT)} {path.stat().st_size}B ← {url}")
        print(f"    {statuses}")
        runs.append((url, attempt_id, output, raws, elapsed))
    return runs, problems


def _check_completed(runs: list[Run]) -> list[str]:
    """① 출구 파일을 되읽어 정본 1.3 모양인지 — 키 셋(실패사유 없음)·도메인단위 키·기록 5개 이름 순서·최상위 None 없음·전체상태 완료·꼬리표 일치·반환값과 파일 동일."""
    problems: list[str] = []
    if len(runs) != DOMAIN_SAMPLES + IP_SAMPLES:
        problems.append(f"① 실행 {len(runs)}건 (기대 {DOMAIN_SAMPLES + IP_SAMPLES})")
    for url, attempt_id, output, _raws, _elapsed in runs:
        saved = json.loads((OUT_ROOT / output_key(JOB_ID, attempt_id)).read_text(encoding="utf-8"))
        if saved != output:
            problems.append(f"① 파일과 반환값이 다름 ← {url}")
        if set(saved) != OUTPUT_KEYS:
            problems.append(f"① 출구 키 {sorted(saved)} (기대 {sorted(OUTPUT_KEYS)}) ← {url}")
        if set(saved.get(KEY_DOMAIN_UNITS, {})) != set(UNIT_KEYS.values()):
            problems.append(f"① 도메인단위 키 {sorted(saved.get(KEY_DOMAIN_UNITS, {}))} ← {url}")
        records = saved.get(KEY_INFRA_RECORDS, [])
        if tuple(r.get("name") for r in records) != RECORD_NAMES:
            problems.append(f"① 기록 다섯이 아님 {[r.get('name') for r in records]} ← {url}")
        for record in records:
            if any(value is None for value in record.values()):
                problems.append(f"① None 칸이 남음 {record} ← {url}")
            if "status" not in record:
                problems.append(f"① status 없는 기록 {record} ← {url}")
        if saved.get(KEY_OVERALL) != OVERALL_COMPLETED:
            problems.append(f"① 전체상태 {saved.get(KEY_OVERALL)!r} (기대 {OVERALL_COMPLETED!r}) ← {url}")
        if saved.get(KEY_JOB_ID) != JOB_ID or saved.get(KEY_ATTEMPT_ID) != attempt_id:
            problems.append(f"① 꼬리표 {saved.get(KEY_JOB_ID)!r}/{saved.get(KEY_ATTEMPT_ID)!r} (기대 {JOB_ID!r}/{attempt_id!r}) ← {url}")
    first_domain = next((run for run in runs if _is_domain_run(run)), None)
    if first_domain is not None:
        print(f"[① 출구 전문 {first_domain[1]}] {output_key(JOB_ID, first_domain[1])}")
        print(json.dumps(first_domain[2], ensure_ascii=False, indent=2))
    return problems


def _check_our_fault() -> list[str]:
    """② 대조는 침묵 주소로, DNS 조회는 즉시 Timeout 대역으로, RDAP은 SLOW_S초 자는 대역으로 갈아 끼우고 run.
    기대: 전체상태 실패 · 사유 대조 무응답 · 기록은 Timeout만 · RDAP 대역이 끝나기 전에 돌아옴(걸린 초 < SLOW_S)."""
    problems: list[str] = []
    rdap_finished = threading.Event()

    def fake_query_dns(fqdn: str, record_type: str) -> tuple[InfraRecord, dict[str, str]]:
        return InfraRecord(_NAME_BY_TYPE[record_type], INFRA_STATUS_TIMEOUT, None, {"elapsed_s": 0.0}, "검증용 Timeout"), {}

    def slow_query_rdap(registrable_unit: str) -> tuple[InfraRecord, dict[str, str]]:
        time.sleep(SLOW_S)
        rdap_finished.set()
        return InfraRecord(NAME_RDAP, INFRA_STATUS_RECEIVED, {"registered": False}, {"elapsed_s": SLOW_S}), {}

    def silent_probes() -> Probes:
        return Probes(resolver=_silent_resolver(), http_url=SILENT_HTTP_URL)

    originals = (handler.Probes, handler.query_dns, handler.query_rdap)
    handler.Probes, handler.query_dns, handler.query_rdap = silent_probes, fake_query_dns, slow_query_rdap
    try:
        started = time.perf_counter()
        output, raws = handler.run("http://example.com/", JOB_ID, "our-fault")
        elapsed = time.perf_counter() - started
        returned_before_rdap = not rdap_finished.is_set()
    finally:
        handler.Probes, handler.query_dns, handler.query_rdap = originals
    save(output, raws, JOB_ID, "our-fault", OUT_ROOT)
    records = output[KEY_INFRA_RECORDS]
    print(f"[② our-fault] {elapsed:.1f}초 {output[KEY_OVERALL]} / {output.get(KEY_FAILURE_REASON)} / 기록 {[(r['name'], r['status']) for r in records]} / RDAP 대역 끝나기 전 반환 {returned_before_rdap}")
    if output[KEY_OVERALL] != OVERALL_FAILED:
        problems.append(f"② 전체상태 {output[KEY_OVERALL]!r} (기대 {OVERALL_FAILED!r})")
    if output.get(KEY_FAILURE_REASON) != FAILURE_PROBE_SILENT:
        problems.append(f"② 실패사유 {output.get(KEY_FAILURE_REASON)!r} (기대 {FAILURE_PROBE_SILENT!r})")
    if not records or any(r["status"] != INFRA_STATUS_TIMEOUT or r["name"] not in _NAME_BY_TYPE.values() for r in records):
        problems.append(f"② 기록 {records} (기대 DNS Timeout 기록만)")
    if not returned_before_rdap or elapsed >= SLOW_S:
        problems.append(f"② 남은 조회를 기다림 — {elapsed:.1f}초, RDAP 대역 끝남 {rdap_finished.is_set()}")
    return problems


def _check_unwritable(runs: list[Run]) -> list[str]:
    """③ 보통 파일 아래를 저장 루트로 주면 mkdir이 NotADirectoryError → 예외가 밖으로 나가고 파일이 없다.
    run은 저장을 안 하므로 ①의 결과를 그 경로에 save로 써서 만든다."""
    problems: list[str] = []
    if not runs:
        return ["③ ①의 실행이 없어 재료 없음"]
    blocker = OUT_ROOT / "not_a_dir"
    blocker.write_text("보통 파일 — 이 아래에는 폴더를 만들 수 없다\n", encoding="utf-8")
    root = blocker / "root"
    url, attempt_id, output, raws, _elapsed = runs[0]
    try:
        save(output, raws, JOB_ID, attempt_id, root)
        raised = "없음"
        problems.append("③ 쓸 수 없는 경로인데 예외 없이 저장됨")
    except OSError as exc:
        raised = f"{type(exc).__name__}: {exc}"
    leftover = [str(p) for p in root.rglob("*")] if root.is_dir() else []
    print(f"[③ {root.relative_to(OUT_ROOT)}] 예외 {raised} / 남은 파일 {len(leftover)}개")
    if leftover:
        problems.append(f"③ 파일이 남음 {leftover}")
    return problems


def _check_budget(runs: list[Run]) -> list[str]:
    """④ 예산을 TINY_BUDGET_S로 갈아 끼우고 ①의 첫 도메인 호스트 URL을 run → 실패 · 사유 예산 초과 · 기록 0개(0건인 이유는 사유 칸) · 곧 돌아옴.
    버려진 진짜 조회는 뒤에서 저 혼자 마감(최대 15초)까지 돈다."""
    problems: list[str] = []
    if not runs:
        return ["④ ①의 실행이 없어 재료 없음"]
    url = next((run[0] for run in runs if _is_domain_run(run)), runs[0][0])
    original = handler.TIME_BUDGET_S
    handler.TIME_BUDGET_S = TINY_BUDGET_S
    try:
        started = time.perf_counter()
        output, raws = handler.run(url, JOB_ID, "budget")
        elapsed = time.perf_counter() - started
    finally:
        handler.TIME_BUDGET_S = original
    save(output, raws, JOB_ID, "budget", OUT_ROOT)
    records = output[KEY_INFRA_RECORDS]
    print(f"[④ budget] {elapsed:.3f}초 {output[KEY_OVERALL]} / {output.get(KEY_FAILURE_REASON)} / 기록 {len(records)}개 / 원본 {len(raws)}개 ← {url}")
    if output[KEY_OVERALL] != OVERALL_FAILED:
        problems.append(f"④ 전체상태 {output[KEY_OVERALL]!r} (기대 {OVERALL_FAILED!r})")
    if output.get(KEY_FAILURE_REASON) != FAILURE_BUDGET_EXCEEDED:
        problems.append(f"④ 실패사유 {output.get(KEY_FAILURE_REASON)!r} (기대 {FAILURE_BUDGET_EXCEEDED!r})")
    if records:
        problems.append(f"④ 기록 {len(records)}개 (기대 0 — 예산 안에 끝난 조회가 없다)")
    if elapsed >= 2.0:
        problems.append(f"④ {elapsed:.1f}초 걸림 (기대 2초 미만)")
    return problems


def _check_raw(runs: list[Run]) -> list[str]:
    """⑤ ①의 실행마다 raw/…/l1/ 아래 — 원본이 있는 기록마다 이름표대로 파일이 있고 내용이 반환값과 같다, 응답 수신 기록은 원본이 있다,
    Not Queried 기록은 파일이 없다. RDAP 200(여섯 조각)은 원본 본문이 JSON으로 되읽힌다."""
    problems: list[str] = []
    for url, attempt_id, output, raws, _elapsed in runs:
        raw_dir = OUT_ROOT / "raw" / JOB_ID / attempt_id / "l1"
        files = sorted(f"{p.name} {p.stat().st_size}B" for p in raw_dir.iterdir()) if raw_dir.is_dir() else []
        print(f"[⑤ {attempt_id}] {files}")
        for record in output[KEY_INFRA_RECORDS]:
            name, status = record["name"], record["status"]
            path = OUT_ROOT / raw_key(JOB_ID, attempt_id, name)
            raw = raws.get(name, {})
            if raw:
                if not path.is_file():
                    problems.append(f"⑤ 원본 파일 없음 {RAW_FILE_BY_NAME[name]} ← {url}")
                elif json.loads(path.read_text(encoding="utf-8")) != raw:
                    problems.append(f"⑤ 파일 내용이 반환 원본과 다름 {RAW_FILE_BY_NAME[name]} ← {url}")
            elif path.exists():
                problems.append(f"⑤ 원본이 비었는데 파일 있음 {RAW_FILE_BY_NAME[name]} ← {url}")
            if status == INFRA_STATUS_RECEIVED and not raw:
                problems.append(f"⑤ 응답 수신인데 원본 없음 {name} ← {url}")
            if status == INFRA_STATUS_NOT_QUERIED and raw:
                problems.append(f"⑤ Not Queried인데 원본 있음 {name} ← {url}")
            if name == NAME_RDAP and isinstance(record.get("result"), dict) and "registered" not in record["result"] and raw:
                text = next(iter(raw.values()))
                body = text.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in text else ""
                try:
                    json.loads(body)
                except ValueError:
                    problems.append(f"⑤ RDAP 원본 본문이 JSON으로 되읽히지 않음 ← {url}")
    first_domain = next((run for run in runs if _is_domain_run(run)), None)
    if first_domain is not None and first_domain[3].get(NAME_DNS_A):
        key, text = next(iter(first_domain[3][NAME_DNS_A].items()))
        print(f"[⑤ 원본 예 {first_domain[1]} {RAW_FILE_BY_NAME[NAME_DNS_A]}] {key!r} →")
        for line in text.splitlines():
            print(f"    {line}")
    return problems


def _is_domain_run(run: Run) -> bool:
    return run[2][KEY_DOMAIN_UNITS][UNIT_KEYS["host_kind"]] == HOST_DOMAIN


if __name__ == "__main__":
    sys.exit(main())
