"""handler.py — URL 한 건의 L1 실행을 조립한다: 입구 → 도메인 단위 → 인프라 조회(DNS·RDAP 동시, A가 끝나면 IP·ASN) → 기록마다 Timeout 판별 → 출구.

실행 순서와 중단 결정을 가진 유일한 자리이고, 부품 전부와 records를 가져오는 유일한 파일이다.
본체 run은 저장하지 않고 (출구, 원본)을 돌려준다 — 저장은 부르는 판이 한다(검증 → records.save 로컬 / lambda_handler → records_s3.save).
"""

import os
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, TimeoutError as FuturesTimeoutError, wait
from dataclasses import replace

from src.common import (
    FAILURE_BUDGET_EXCEEDED,
    FAILURE_PROBE_SILENT,
    NAME_DNS_A,
    NAME_DNS_NS,
    NAME_DNS_NS_REGISTRABLE,
    NAME_IP_ASN,
    NAME_RDAP,
    InfraRecord,
    INFRA_STATUS_TOOL_ERROR,
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
_RECORD_NAMES: tuple[str, ...] = (NAME_DNS_A, NAME_DNS_NS,
    NAME_DNS_NS_REGISTRABLE, NAME_IP_ASN, NAME_RDAP)


def run(url_raw: str, job_id: str, attempt_id: str) -> tuple[dict, dict[str, dict[str, str]]]:
    """입구 셋 → (출구 dict, 관측 이름별 원본). 입구 파싱 예외는 잡지 않는다 — 출구가 안 만들어지는 것이 실패 ①의 표기다."""
    probes = Probes()   # 실행마다 새로 — 모듈 변수면 Lambda 재사용 컨테이너에서 지난 실행의 대조 답을 물려받는다
    deadline = time.monotonic() + TIME_BUDGET_S   # 모듈 이름을 실행 때 읽는다 — 검증 ④가 이 이름을 갈아 끼운다
    fqdn = extract_fqdn(url_raw)
    units = compute_domain_units(fqdn)
    lifecycle=[]
    records, raws, failure_reason = _query_infra(fqdn, units, probes, deadline, lifecycle=lifecycle)
    output=build_output(job_id, attempt_id, units, records, failure_reason)
    output['target']={'original_url':url_raw, 'lookup_host':fqdn}
    output['query_lifecycle']=lifecycle
    ns_comparison=(_compare_registration_ns(records, units.registrable_unit, fqdn)
                   if failure_reason is None else None)
    if ns_comparison is not None:
        output['ns_registration_comparison']=ns_comparison
    for item in output['인프라결과_목록']:
        observation=item['observation']
        target=units.registrable_unit if item['name'] in (NAME_RDAP, NAME_DNS_NS_REGISTRABLE) else fqdn if item['name']!=NAME_IP_ASN else None
        observation['query_target']=target
        observation['technical_scope']='Recorded lookup response; lookup result and platform-list match do not establish site operator, intent or maliciousness.'
        if item['status'] in ('Timeout','도구 오류') and not observation['limitations']:
            observation['limitations']=[{'code':'infrastructure_timeout' if item['status']=='Timeout' else 'infrastructure_tool_error',
                'occurrence_id':f"l1:query:{item['name']}",'stage':'infrastructure_lookup','impact_scope':'acquisition',
                'target':target,'name':item['name'],'reason':item.get('reason'),'detail':item.get('detail')}]
    return output, raws


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
    fqdn: str, units: DomainUnits, probes: Probes, deadline: float, *, lifecycle=None
) -> tuple[list[InfraRecord], dict[str, dict[str, str]], str | None]:
    """기본 조회 넷과, 대상이 다를 때 등록 단위 NS를 돌린다.

    풀은 with 없이 만든다 — with의 __exit__은 shutdown(wait=True)라 도는 조회를 15초까지 기다린다.
    「버리고 떠남」의 실체는 finally의 shutdown(wait=False, cancel_futures=True): 시작 안 한 것은 취소, 도는 것은 안 기다린다.
    """
    done: dict[str, InfraRecord] = {}
    raws: dict[str, dict[str, str]] = {}
    future_names={}
    ip_asn_targets: tuple[str,...]=()
    active_names=(_RECORD_NAMES if units.host_kind == HOST_DOMAIN and fqdn != units.registrable_unit
                  else tuple(name for name in _RECORD_NAMES if name != NAME_DNS_NS_REGISTRABLE))
    def finish(reason):
        if lifecycle is not None:
            # Snapshot actual future states; no unfinished query is called a timeout.
            by_name={name:f for f,name in future_names.items()}
            for name in active_names:
                future=by_name.get(name)
                if name in done:
                    state='result_recorded'
                elif future is None:
                    state='not_started'
                elif future.cancelled() or future.cancel():
                    state='cancelled_before_start'
                elif future.done():
                    state='completed_result_not_consumed'
                else:
                    state='running_at_stop'
                lifecycle.append({'name':name,'state':state,'run_stop_reason':reason,
                    'raw_response_recorded':name in raws,
                    'result_status':done[name].status if name in done else None})
        return _finish(done,raws,reason)
    pool = ThreadPoolExecutor(max_workers=5)
    try:
        if units.host_kind == HOST_DOMAIN:
            # URL 호스트의 DNS 셋과 RDAP, 필요하면 등록 단위 NS를 함께 시작한다.
            # A가 끝나는 순간(RDAP이 아직 돌아도) IP·ASN을 같은 풀에 넣는다.
            # as_completed를 안 쓰는 이유: 도는 중에 future를 더 넣을 수 없다 — wait(FIRST_COMPLETED) 루프는 pending에 더할 수 있다.
            dns_names = {"A":NAME_DNS_A,"NS":NAME_DNS_NS}
            future_names = {pool.submit(query_dns,fqdn,t):dns_names[t] for t in dns_names}
            address_futures = {f for f,n in future_names.items() if n == NAME_DNS_A}
            rdap_future = pool.submit(query_rdap, units.registrable_unit)
            future_names[rdap_future] = NAME_RDAP
            if fqdn != units.registrable_unit:
                ns_future = pool.submit(_query_registration_ns, units.registrable_unit)
                future_names[ns_future] = NAME_DNS_NS_REGISTRABLE
            pending = set(future_names)
            ip_asn_started = False
            while pending:
                # 대기 한도는 매번 남은 예산이라, 사이에 대조(최대 15초)가 끼어도 마감이 밀리지 않는다.
                finished, pending = wait(pending, timeout=_remaining(deadline), return_when=FIRST_COMPLETED)
                if not finished:
                    # 남은 예산 안에 끝난 조회가 없다 = 예산 소진. 미완 조회의 기록은 만들지 않는다.
                    return finish(FAILURE_BUDGET_EXCEEDED)
                for future in finished:
                    try:
                        record, raw = future.result()
                    except Exception as exc:
                        detail={"code":"collector_exception", "error_type":type(exc).__name__}
                        if future_names[future]==NAME_IP_ASN and ip_asn_targets:
                            detail['query_targets']=list(ip_asn_targets)
                        record, raw = InfraRecord(future_names[future], INFRA_STATUS_TOOL_ERROR, None,
                            detail, str(exc)), {}
                    if _accept(record, raw, done, raws, probes) == VERDICT_OUR_FAULT:
                        return finish(FAILURE_PROBE_SILENT)
                if not ip_asn_started and address_futures.isdisjoint(pending):
                    # A가 pending에서 빠졌다 — A 기록의 첫 두 고유 IPv4로 IP·ASN을 시작한다.
                    ip_asn_started = True
                    ip_asn_targets=_collect_ips(_in_order(done))
                    asn_future = pool.submit(query_ip_asn, ip_asn_targets)
                    future_names[asn_future] = NAME_IP_ASN
                    pending.add(asn_future)
            return finish(None)
        else:
            for record in (*not_queried_dns(), not_queried_rdap()):
                _accept(record, {}, done, raws, probes)   # 물은 게 없어 Timeout일 수 없다 — 판별은 늘 「Timeout 아님」
            # 입구는 IPv6를 대괄호 포함으로 주는데 Cymru 질의 이름은 대괄호를 모른다.
            ips = (fqdn[1:-1] if fqdn.startswith("[") and fqdn.endswith("]") else fqdn,)
            try:
                asn_future=pool.submit(query_ip_asn, ips)
                future_names[asn_future]=NAME_IP_ASN
                record, raw = asn_future.result(timeout=_remaining(deadline))
            except FuturesTimeoutError:
                raise
            except Exception as exc:
                record, raw = InfraRecord(NAME_IP_ASN, INFRA_STATUS_TOOL_ERROR, None,
                    {"code":"collector_exception", "error_type":type(exc).__name__}, str(exc)), {}
            if _accept(record, raw, done, raws, probes) == VERDICT_OUR_FAULT:
                return finish(FAILURE_PROBE_SILENT)
            return finish(None)
    except FuturesTimeoutError:
        # IP 호스트 경로의 result(timeout=남은 예산)가 한도를 넘긴 것. 도메인 경로의 예산 소진은 위 루프가 빈 finished로 잡는다.
        return finish(FAILURE_BUDGET_EXCEEDED)
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


def _accept(record: InfraRecord, raw: dict[str, str], done: dict[str, InfraRecord], raws: dict[str, dict[str, str]], probes: Probes) -> str:
    """끝난 기록 하나를 받아 두고 Timeout 판별 결과를 돌려준다. 원본이 비면 raws에 넣지 않는다."""
    done[record.name] = record
    if raw:
        raws[record.name] = raw
    return judge_timeout(record, probes)


def _query_registration_ns(registrable_unit: str) -> tuple[InfraRecord, dict[str, str]]:
    """Keep the registration-unit lookup distinct from the URL-host NS lookup."""
    record, raw = query_dns(registrable_unit, "NS")
    return replace(record, name=NAME_DNS_NS_REGISTRABLE), raw


def _compare_registration_ns(records: list[InfraRecord], registrable_unit: str, fqdn: str) -> dict | None:
    """Compare two observed NS lists for the same registered domain, without a URL verdict."""
    by_name={record.name:record for record in records}
    ns_name=NAME_DNS_NS if fqdn == registrable_unit else NAME_DNS_NS_REGISTRABLE
    ns=by_name.get(ns_name)
    rdap=by_name.get(NAME_RDAP)
    if ns is None or rdap is None or ns.status != '응답 수신' or rdap.status != '응답 수신':
        return None
    dns_values=ns.result.get('records') if isinstance(ns.result,dict) else None
    rdap_values=rdap.result.get('nameservers') if isinstance(rdap.result,dict) else None
    if not (isinstance(dns_values,list) and dns_values and all(isinstance(x,str) for x in dns_values)
            and isinstance(rdap_values,list) and rdap_values and all(isinstance(x,str) for x in rdap_values)):
        return None
    normalized=lambda values: {item.rstrip('.').casefold() for item in values}
    return {'domain':registrable_unit,'dns_lookup':ns_name,'rdap_lookup':NAME_RDAP,
            'same_set':normalized(dns_values)==normalized(rdap_values),
            'scope':'DNS response and RDAP registration data at the same domain; set equality is not a URL verdict.'}


def _finish(
    done: dict[str, InfraRecord], raws: dict[str, dict[str, str]], failure_reason: str | None
) -> tuple[list[InfraRecord], dict[str, dict[str, str]], str | None]:
    return _in_order(done), {name: raws[name] for name in _RECORD_NAMES if name in raws}, failure_reason


def _in_order(done: dict[str, InfraRecord]) -> list[InfraRecord]:
    return [done[name] for name in _RECORD_NAMES if name in done]


def _collect_ips(dns_records: list[InfraRecord]) -> tuple[str, ...]:
    """A 응답 순서의 첫 두 고유 IPv4만 고른다. 부정 응답은 조회 대상이 없다."""
    ips: list[str] = []
    for record in dns_records:
        if record.name == NAME_DNS_A and isinstance(record.result, dict):
            for ip in record.result.get("records", []):
                if ip not in ips:
                    ips.append(ip)
                    if len(ips) == 2:
                        return tuple(ips)
    return tuple(ips)


def _remaining(deadline: float) -> float:
    return max(0.0, deadline - time.monotonic())
