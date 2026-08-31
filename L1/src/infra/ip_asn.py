"""ip_asn.py — DNS가 준 IP들을 Team Cymru에 물어 IP·ASN 기록 하나로 모으고, 받은 TXT 응답의 원본을 함께 돌려준다."""

import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor

import dns.rdata
import dns.resolver

from src.common import (
    DNS_LIFETIME_S,
    DNS_TIMEOUT_S,
    INFRA_STATUS_NOT_QUERIED,
    INFRA_STATUS_RECEIVED,
    INFRA_STATUS_TIMEOUT,
    INFRA_STATUS_TOOL_ERROR,
    NAME_IP_ASN,
    InfraRecord,
)

__all__ = ["query_ip_asn", "REASON_NO_IPS"]

REASON_NO_IPS: str = "DNS가 IP를 주지 않아 물을 대상이 없음"

_ORIGIN_SUFFIX_V4: str = "origin.asn.cymru.com"
_ORIGIN_SUFFIX_V6: str = "origin6.asn.cymru.com"
_ASN_SUFFIX: str = "asn.cymru.com"


def query_ip_asn(ips: tuple[str, ...]) -> tuple[InfraRecord, dict[str, str]]:
    """중복을 뺀 IP들 → 기록 하나. 첫 단계(역순 IP)는 IP 개수만큼 동시에, 둘째 단계(조직 이름)는 번호마다 한 번씩 순서대로.

    둘째 값은 원본 — {질의 이름 TXT: 응답 메시지 텍스트}, IP마다 한 질의 + AS 번호마다 한 질의 만큼. 받은 것이 없으면 빈 dict.
    """
    if not ips:
        return InfraRecord(NAME_IP_ASN, INFRA_STATUS_NOT_QUERIED, reason=REASON_NO_IPS), {}
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=len(ips)) as pool:
        outcomes = list(pool.map(_query_origin, ips))

    raw: dict[str, str] = {}
    result: dict = {}
    dropped: dict[str, str] = {}
    origin_answers: dict[str, list[str]] = {}
    failures: list[BaseException] = []
    org_by_asn: dict[str, str | None] = {}   # 같은 번호는 한 번만 묻는다. None = 물었지만 값이 없었음
    org_failure_by_asn: dict[str, str] = {}
    for ip, (value, lines, origin_raw) in zip(ips, outcomes):
        raw.update(origin_raw)   # 형식이 안 맞아 값이 예외가 된 IP도 응답은 받았으니 원본은 남는다
        if isinstance(value, BaseException):
            failures.append(value)
            dropped[ip] = str(value)
            continue
        if len(lines) > 1:
            origin_answers[ip] = lines
        if isinstance(value, dict) and value:
            asn = value["asn"].split()[0]   # 번호가 여럿이면 첫 번호만 묻는다
            if asn not in org_by_asn and asn not in org_failure_by_asn:
                try:
                    org, org_raw = _query_org(asn)
                    org_by_asn[asn] = org
                    raw.update(org_raw)
                except Exception as exc:
                    org_failure_by_asn[asn] = str(exc)
            if org_by_asn.get(asn) is not None:
                value["org"] = org_by_asn[asn]
            else:
                dropped[ip] = "조직 이름 조회 실패: " + org_failure_by_asn.get(asn, "응답에 TXT 없음(NoAnswer)")
        result[ip] = value

    detail: dict = {"elapsed_s": round(time.perf_counter() - started, 3)}
    if len(failures) == len(ips):
        # 전부 못 받았을 때만 실패. 하나라도 끝까지 기다린 timeout이면 Timeout, 아니면 도구 오류.
        timed_out = any(isinstance(exc, dns.resolver.LifetimeTimeout) for exc in failures)
        status = INFRA_STATUS_TIMEOUT if timed_out else INFRA_STATUS_TOOL_ERROR
        return InfraRecord(NAME_IP_ASN, status, None, detail, " / ".join(str(exc) for exc in failures)), raw
    if origin_answers:
        detail["origin_answers"] = origin_answers
    if dropped:
        detail["dropped"] = dropped
    return InfraRecord(NAME_IP_ASN, INFRA_STATUS_RECEIVED, result, detail), raw


def _query_origin(ip: str) -> tuple[dict | str | BaseException, list[str], dict[str, str]]:
    """IP 하나 → (값, 받은 TXT 줄 전부, 원본). 값은 네 값 묶음(org 제외) 또는 NXDOMAIN·SERVFAIL 문자열, NoAnswer면 {}. 예외는 값으로 돌려준다."""
    try:
        qname = _origin_qname(ip)
    except ValueError as exc:   # IP 표기가 아닌 입력 — 예전과 같이 예외를 값으로 돌려준다
        return exc, [], {}
    key = f"{qname} TXT"
    try:
        answer = _RESOLVER.resolve(qname, "TXT")
    except dns.resolver.NXDOMAIN as exc:
        return "NXDOMAIN", [], _raw(key, exc.kwargs.get("responses", {}).values())
    except dns.resolver.NoNameservers as exc:
        return "SERVFAIL", [], _raw(key, (error[-1] for error in exc.kwargs.get("errors", ())))
    except dns.resolver.NoAnswer as exc:
        return {}, [], _raw(key, (exc.kwargs.get("response"),))
    except Exception as exc:
        return exc, [], {}
    raw = _raw(key, (answer.response,))
    lines = [_txt(rdata) for rdata in answer]
    try:
        parsed = [_parse_origin(line) for line in lines]
        # 대역이 겹쳐 줄이 여럿이면 가장 좁은 대역(prefix 길이 최대)이 그 IP를 실제로 담당하는 줄이다.
        chosen = max(parsed, key=lambda bundle: int(bundle["prefix"].rsplit("/", 1)[1]))
    except (IndexError, ValueError) as exc:
        return ValueError(f"Cymru 응답 형식이 아님: {lines} ({exc})"), lines, raw
    return chosen, lines, raw


def _query_org(asn: str) -> tuple[str | None, dict[str, str]]:
    """AS 번호 → (조직 이름, 원본). NXDOMAIN·SERVFAIL은 그 말 그대로, TXT가 없으면 None. 예외는 그대로 나간다."""
    qname = _asn_qname(asn)
    key = f"{qname} TXT"
    try:
        answer = _RESOLVER.resolve(qname, "TXT")
    except dns.resolver.NXDOMAIN as exc:
        return "NXDOMAIN", _raw(key, exc.kwargs.get("responses", {}).values())
    except dns.resolver.NoNameservers as exc:
        return "SERVFAIL", _raw(key, (error[-1] for error in exc.kwargs.get("errors", ())))
    except dns.resolver.NoAnswer as exc:
        return None, _raw(key, (exc.kwargs.get("response"),))
    return _parse_org(_txt(next(iter(answer)))), _raw(key, (answer.response,))


def _raw(key: str, responses) -> dict[str, str]:
    """받은 메시지들 → {물은 것: 텍스트}. dns.py와 같은 함수 — 부품끼리 import하지 않아 여기 한 번 더 둔다."""
    texts = [response.to_text() for response in responses if response is not None]
    return {key: "\n\n".join(texts)} if texts else {}


def _origin_qname(ip: str) -> str:
    # 역순 표기와 IPv6 니블 전개는 표준 라이브러리의 reverse_pointer에 맡기고 끝 부분만 Cymru 이름으로 바꾼다.
    pointer = ipaddress.ip_address(ip).reverse_pointer
    if pointer.endswith(".ip6.arpa"):
        return pointer[: -len(".ip6.arpa")] + "." + _ORIGIN_SUFFIX_V6
    return pointer[: -len(".in-addr.arpa")] + "." + _ORIGIN_SUFFIX_V4


def _asn_qname(asn: str) -> str:
    return f"AS{asn}.{_ASN_SUFFIX}"


def _txt(rdata: dns.rdata.Rdata) -> str:
    # dnspython은 TXT를 바이트 조각들로 주므로 이어 붙여 바깥 따옴표 없는 한 줄로 만든다.
    return b"".join(rdata.strings).decode("utf-8", errors="replace")


def _parse_origin(line: str) -> dict[str, str]:
    # "23028 | 216.90.108.0/24 | US | arin | 1998-09-25" — 뒤 두 조각(레지스트리·할당일)은 기록 축소로 담지 않는다.
    pieces = [piece.strip() for piece in line.split("|")]
    if len(pieces) != 5:
        raise ValueError(f"조각 {len(pieces)}개")
    return {"asn": pieces[0], "prefix": pieces[1], "country": pieces[2]}


def _parse_org(line: str) -> str:
    # "23028 | US | arin | 2002-01-04 | TEAM-CYMRU - Team Cymru, Inc., US" — 다섯째 조각이 조직 이름.
    return line.split("|")[-1].strip()


# dns.py와 같은 설정의 별도 객체. 부품끼리 import하지 않고 common에 리졸버를 두지 않으므로 여기 한 번 더 만든다.
_RESOLVER: dns.resolver.Resolver = dns.resolver.Resolver()
_RESOLVER.timeout = DNS_TIMEOUT_S
_RESOLVER.lifetime = DNS_LIFETIME_S
