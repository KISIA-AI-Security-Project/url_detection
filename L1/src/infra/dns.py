"""dns.py — FQDN 하나·레코드 종류 하나를 리졸버에 물어 기록 하나와 받은 응답의 원본을 만든다."""

import time

import dns.message
import dns.rdatatype
import dns.resolver

from src.common import (
    DNS_LIFETIME_S,
    DNS_TIMEOUT_S,
    INFRA_STATUS_NOT_QUERIED,
    INFRA_STATUS_RECEIVED,
    INFRA_STATUS_TIMEOUT,
    INFRA_STATUS_TOOL_ERROR,
    NAME_DNS_A,
    NAME_DNS_AAAA,
    NAME_DNS_NS,
    REASON_HOST_IS_IP,
    InfraRecord,
)

__all__ = ["query_dns", "not_queried_dns"]


def query_dns(fqdn: str, record_type: str) -> tuple[InfraRecord, dict[str, str]]:
    """record_type은 "A" / "AAAA" / "NS" 중 하나. 예외는 전부 상태 어휘로 바꿔 돌려주고 밖으로 내지 않는다.

    둘째 값은 원본 — {물은 것: 받은 응답 메시지의 텍스트}. 응답 메시지가 있으면 status와 무관하게 남기고, 받은 것이 없으면 빈 dict.
    """
    name = _NAME_BY_TYPE[record_type]
    key = f"{fqdn} {record_type}"
    started = time.perf_counter()
    try:
        answer = _RESOLVER.resolve(fqdn, record_type)
    except dns.resolver.NXDOMAIN as exc:
        # 부정 응답에도 메시지가 있다(AUTHORITY의 SOA가 부정 캐시 TTL을 준다). 예외가 qname별로 든 응답을 원본으로 남긴다.
        return InfraRecord(name, INFRA_STATUS_RECEIVED, "NXDOMAIN", _detail(started)), _raw(key, exc.kwargs.get("responses", {}).values())
    except dns.resolver.NoNameservers as exc:
        # 서버별 (nameserver, tcp, port, 예외, response) 묶음 — response가 있는 것(SERVFAIL로 답한 서버)만 원본이 된다.
        return InfraRecord(name, INFRA_STATUS_RECEIVED, "SERVFAIL", _detail(started)), _raw(key, (error[-1] for error in exc.kwargs.get("errors", ())))
    except dns.resolver.NoAnswer as exc:
        # 물은 종류는 없고 CNAME 체인만 온 응답. 체인은 예외에 딸린 response에 있다.
        response = exc.kwargs.get("response")
        return InfraRecord(name, INFRA_STATUS_RECEIVED, {"records": []}, _detail(started, response)), _raw(key, (response,))
    except dns.resolver.LifetimeTimeout as exc:
        return InfraRecord(name, INFRA_STATUS_TIMEOUT, None, _detail(started), str(exc)), {}
    except Exception as exc:
        return InfraRecord(name, INFRA_STATUS_TOOL_ERROR, None, _detail(started), str(exc)), {}
    return _record_from_answer(answer, name, started), _raw(key, (answer.response,))


def not_queried_dns() -> tuple[InfraRecord, InfraRecord, InfraRecord]:
    """호스트가 IP라 묻지 않았을 때의 기록 셋(A·AAAA·NS 순서)."""
    return (
        InfraRecord(NAME_DNS_A, INFRA_STATUS_NOT_QUERIED, reason=REASON_HOST_IS_IP),
        InfraRecord(NAME_DNS_AAAA, INFRA_STATUS_NOT_QUERIED, reason=REASON_HOST_IS_IP),
        InfraRecord(NAME_DNS_NS, INFRA_STATUS_NOT_QUERIED, reason=REASON_HOST_IS_IP),
    )


def _record_from_answer(answer: dns.resolver.Answer, name: str, started: float) -> InfraRecord:
    # ttl은 레코드 하나가 아니라 같은 종류 묶음(rrset) 전체에 하나 붙는 값이라 records 옆에 둔다.
    result = {"records": [rdata.to_text() for rdata in answer.rrset], "ttl": answer.rrset.ttl}
    return InfraRecord(name, INFRA_STATUS_RECEIVED, result, _detail(started, answer.response))


def _detail(started: float, response: dns.message.Message | None = None) -> dict:
    detail: dict = {"elapsed_s": round(time.perf_counter() - started, 3)}
    chain = _cname_chain(response) if response is not None else []
    if chain:
        detail["cname_chain"] = chain
    return detail


def _raw(key: str, responses) -> dict[str, str]:
    """받은 메시지들 → {물은 것: 텍스트}. to_text()는 dig 꼴(rcode·flags·네 섹션)이고 from_text()로 되읽힌다.
    메시지가 여럿(서버 여럿이 SERVFAIL로 답한 경우)이면 빈 줄로 이어 붙이고, 하나도 없으면 빈 dict."""
    texts = [response.to_text() for response in responses if response is not None]
    return {key: "\n\n".join(texts)} if texts else {}


def _cname_chain(response: dns.message.Message) -> list[str]:
    # rrset.to_text()는 "소유자 TTL IN CNAME 대상" 한 줄이라 체인의 원문이 그대로 남는다.
    return [rrset.to_text() for rrset in response.answer if rrset.rdtype == dns.rdatatype.CNAME]


_NAME_BY_TYPE: dict[str, str] = {"A": NAME_DNS_A, "AAAA": NAME_DNS_AAAA, "NS": NAME_DNS_NS}

# dnspython 기본(2초·5초)은 DIG와 달라, 공용 상수(시도당 5초 × 3회)로 맞춘다. 대조(failure.py)도 같은 값을 읽는다.
_RESOLVER: dns.resolver.Resolver = dns.resolver.Resolver()
_RESOLVER.timeout = DNS_TIMEOUT_S
_RESOLVER.lifetime = DNS_LIFETIME_S
