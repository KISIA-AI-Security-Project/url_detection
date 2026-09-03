"""handler.py — URL 한 건의 L1 실행을 조립한다: 입구 → 도메인 단위 → 인프라 조회(DNS 3종·RDAP 동시, DNS 셋이 끝나면 IP·ASN) → 기록마다 Timeout 판별 → 출구.

실행 순서와 중단 결정을 가진 유일한 자리이고, 부품 전부와 records를 가져오는 유일한 파일이다.
본체 run은 저장하지 않고 (출구, 원본)을 돌려준다 — 저장은 부르는 판이 한다(검증 → records.save 로컬 / lambda_handler → records_s3.save).
"""

import os
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, TimeoutError as FuturesTimeoutError, wait

from src.common import (
    FAILURE_BUDGET_EXCEEDED,
    FAILURE_PROBE_SILENT,
    NAME_DNS_A,
    NAME_DNS_AAAA,
    NAME_DNS_NS,
    NAME_IP_ASN,
    NAME_RDAP,
    InfraRecord,
)
from src.domain_units import HOST_DOMAIN, DomainUnits, compute_domain_units
from src.entry import extract_fqdn
from src.failure import TIME_BUDGET_S, VERDICT_OUR_FAULT, Probes, judge_timeout
from src.infra.dns import not_queried_dns, query_dns
from src.infra.ip_asn import query_ip_asn
from src.infra.rdap import not_queried_rdap, query_rdap
from src.records import build_output

__all__ = ["run", "lambda_handler"]

# 출구에 적는 기록 순서. 끊긴 실행이면 이 중 끝난 것만 이 순서로.
_RECORD_NAMES: tuple[str, ...] = (NAME_DNS_A, NAME_DNS_AAAA, NAME_DNS_NS, NAME_IP_ASN, NAME_RDAP)


def run(url_raw: str, job_id: str, attempt_id: str) -> tuple[dict, dict[str, dict[str, str]]]:
    """입구 셋 → (출구 dict, 관측 이름별 원본). 입구 파싱 예외는 잡지 않는다 — 출구가 안 만들어지는 것이 실패 ①의 표기다."""
    probes = Probes()   # 실행마다 새로 — 모듈 변수면 Lambda 재사용 컨테이너에서 지난 실행의 대조 답을 물려받는다
    deadline = time.monotonic() + TIME_BUDGET_S   # 모듈 이름을 실행 때 읽는다 — 검증 ④가 이 이름을 갈아 끼운다
    fqdn = extract_fqdn(url_raw)
    units = compute_domain_units(fqdn)
    records, raws, failure_reason = _query_infra(fqdn, units, probes, deadline)
    return build_output(job_id, attempt_id, units, records, failure_reason), raws


def lambda_handler(event: dict, context: object) -> dict:
    """Lambda 진입점. event에서 입구 셋을 변환 없이 꺼내 run을 부르고 S3에 저장한 뒤 출구를 돌려준다.

    context는 읽지 않는다 — 예산 시계는 우리 상수로 잰다. 키가 없으면 KeyError가 그대로 나가 Lambda 오류(실패 ① 출구 미성립)가 된다.
    """
    from src import records_s3   # boto3가 Lambda에만 있어, 로컬 검증이 이 모듈을 import해도 죽지 않게 여기서 가져온다

    job_id, attempt_id = event["job_id"], event["attempt_id"]
    output, raws = run(event["url_raw"], job_id, attempt_id)
    records_s3.save(output, raws, job_id, attempt_id, os.environ["OUTPUT_BUCKET"])   # 팀 공용 산출물 버킷 — 계층별 버킷이 아니라 이 이름
    return output


def _query_infra(
    fqdn: str, units: DomainUnits, probes: Probes, deadline: float
) -> tuple[list[InfraRecord], dict[str, dict[str, str]], str | None]:
    """조회 다섯을 돌려 (끝난 기록 — 이름 순서, 이름별 원본, 실패사유 또는 None)을 낸다.

    풀은 with 없이 만든다 — with의 __exit__은 shutdown(wait=True)라 도는 조회를 15초까지 기다린다.
    「버리고 떠남」의 실체는 finally의 shutdown(wait=False, cancel_futures=True): 시작 안 한 것은 취소, 도는 것은 안 기다린다.
    """
    done: dict[str, InfraRecord] = {}
    raws: dict[str, dict[str, str]] = {}
    pool = ThreadPoolExecutor(max_workers=4)
    try:
        if units.host_kind == HOST_DOMAIN:
            # DNS 셋과 RDAP을 동시에 내보내고, DNS 셋이 끝나는 순간(RDAP이 아직 돌아도) IP·ASN을 같은 풀에 넣는다.
            # as_completed를 안 쓰는 이유: 도는 중에 future를 더 넣을 수 없다 — wait(FIRST_COMPLETED) 루프는 pending에 더할 수 있다.
            dns_futures = {pool.submit(query_dns, fqdn, record_type) for record_type in ("A", "AAAA", "NS")}
            pending = dns_futures | {pool.submit(query_rdap, units.registrable_unit)}
            ip_asn_started = False
            while pending:
                # 대기 한도는 매번 남은 예산이라, 사이에 대조(최대 15초)가 끼어도 마감이 밀리지 않는다.
                finished, pending = wait(pending, timeout=_remaining(deadline), return_when=FIRST_COMPLETED)
                if not finished:
                    # 남은 예산 안에 끝난 조회가 없다 = 예산 소진. 미완 조회의 기록은 만들지 않는다.
                    return _finish(done, raws, FAILURE_BUDGET_EXCEEDED)
                for future in finished:
                    record, raw = future.result()
                    if _accept(record, raw, done, raws, probes) == VERDICT_OUR_FAULT:
                        return _finish(done, raws, FAILURE_PROBE_SILENT)
                if not ip_asn_started and dns_futures.isdisjoint(pending):
                    # DNS 셋이 전부 pending에서 빠졌다 — A·AAAA 기록의 IP로 IP·ASN을 시작하고 그 future도 같은 루프가 받는다.
                    ip_asn_started = True
                    pending.add(pool.submit(query_ip_asn, _collect_ips(_in_order(done))))
            return _finish(done, raws, None)
        else:
            for record in (*not_queried_dns(), not_queried_rdap()):
                _accept(record, {}, done, raws, probes)   # 물은 게 없어 Timeout일 수 없다 — 판별은 늘 「Timeout 아님」
            # 입구는 IPv6를 대괄호 포함으로 주는데 Cymru 질의 이름은 대괄호를 모른다.
            ips = (fqdn[1:-1] if fqdn.startswith("[") and fqdn.endswith("]") else fqdn,)
            record, raw = pool.submit(query_ip_asn, ips).result(timeout=_remaining(deadline))
            if _accept(record, raw, done, raws, probes) == VERDICT_OUR_FAULT:
                return _finish(done, raws, FAILURE_PROBE_SILENT)
            return _finish(done, raws, None)
    except FuturesTimeoutError:
        # IP 호스트 경로의 result(timeout=남은 예산)가 한도를 넘긴 것. 도메인 경로의 예산 소진은 위 루프가 빈 finished로 잡는다.
        return _finish(done, raws, FAILURE_BUDGET_EXCEEDED)
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


def _accept(record: InfraRecord, raw: dict[str, str], done: dict[str, InfraRecord], raws: dict[str, dict[str, str]], probes: Probes) -> str:
    """끝난 기록 하나를 받아 두고 Timeout 판별 결과를 돌려준다. 원본이 비면 raws에 넣지 않는다."""
    done[record.name] = record
    if raw:
        raws[record.name] = raw
    return judge_timeout(record, probes)


def _finish(
    done: dict[str, InfraRecord], raws: dict[str, dict[str, str]], failure_reason: str | None
) -> tuple[list[InfraRecord], dict[str, dict[str, str]], str | None]:
    return _in_order(done), {name: raws[name] for name in _RECORD_NAMES if name in raws}, failure_reason


def _in_order(done: dict[str, InfraRecord]) -> list[InfraRecord]:
    return [done[name] for name in _RECORD_NAMES if name in done]


def _collect_ips(dns_records: list[InfraRecord]) -> tuple[str, ...]:
    """A·AAAA 기록의 records에서 IP를 처음 나온 순서로 모으고 중복을 뺀다. result가 dict가 아닌 기록(NXDOMAIN 등)은 건너뛴다."""
    ips: list[str] = []
    for record in dns_records:
        if record.name in (NAME_DNS_A, NAME_DNS_AAAA) and isinstance(record.result, dict):
            for ip in record.result.get("records", []):
                if ip not in ips:
                    ips.append(ip)
    return tuple(ips)


def _remaining(deadline: float) -> float:
    return max(0.0, deadline - time.monotonic())
