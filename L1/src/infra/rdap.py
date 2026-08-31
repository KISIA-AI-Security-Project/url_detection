"""rdap.py — 등록 단위의 RDAP 서버를 동봉 표에서 골라 묻고 기록 하나와 받은 HTTP 응답의 원본을 만든다."""

import json
import time
from pathlib import Path

import httpx

from src.common import (
    INFRA_STATUS_NOT_QUERIED,
    INFRA_STATUS_RECEIVED,
    INFRA_STATUS_TIMEOUT,
    INFRA_STATUS_TOOL_ERROR,
    NAME_RDAP,
    REASON_HOST_IS_IP,
    InfraRecord,
)

__all__ = [
    "query_rdap",
    "not_queried_rdap",
    "REASON_NO_RDAP_SERVER",
    "BOOTSTRAP_PATH",
    "SUPPLEMENT_PATH",
    "RDAP_TABLE_VERSION",
]

REASON_NO_RDAP_SERVER: str = "이 접미사의 RDAP 서버를 모름"

# 두 표 모두 모듈 옆에 두어 L1/src/가 통째로 배포되면 따라간다.
BOOTSTRAP_PATH: Path = Path(__file__).with_name("rdap_bootstrap.json")
SUPPLEMENT_PATH: Path = Path(__file__).with_name("rdap_supplement.json")


def query_rdap(registrable_unit: str) -> tuple[InfraRecord, dict[str, str]]:
    """등록 단위 하나 → 기록 하나. 서버를 모르면 Not Queried. 예외는 전부 상태 어휘로 바꿔 돌려준다.

    둘째 값은 원본 — {요청 URL: 상태 줄·헤더·본문 텍스트}. 응답이 있으면 status와 무관하게 남기고(200인데 JSON이 아닌 도구 오류도), 없으면 빈 dict.
    """
    base = _pick_server(registrable_unit)
    if base is None:
        return InfraRecord(
            NAME_RDAP, INFRA_STATUS_NOT_QUERIED, None, {"table_version": RDAP_TABLE_VERSION}, REASON_NO_RDAP_SERVER
        ), {}
    url = base.rstrip("/") + "/domain/" + registrable_unit
    started = time.perf_counter()
    try:
        response = _CLIENT.get(url)
    except httpx.TimeoutException as exc:
        return InfraRecord(NAME_RDAP, INFRA_STATUS_TIMEOUT, None, _detail(started), str(exc)), {}
    except httpx.HTTPError as exc:
        return InfraRecord(NAME_RDAP, INFRA_STATUS_TOOL_ERROR, None, _detail(started), str(exc)), {}

    raw = {url: _http_text(response)}
    detail = _detail(started, response)
    if response.status_code == 404:
        return InfraRecord(NAME_RDAP, INFRA_STATUS_RECEIVED, {"registered": False}, detail), raw
    body = _json_object(response)
    if response.status_code == 200:
        if body is None:
            return InfraRecord(NAME_RDAP, INFRA_STATUS_TOOL_ERROR, None, detail, "응답이 RDAP JSON이 아님"), raw
        # 200인데 JSON 모양이 예상 밖(필드가 null 등)이면 부품 밖으로 예외를 내지 않고 도구 오류로 돌려준다.
        try:
            result = _parse_domain(body)
        except Exception as exc:
            return InfraRecord(NAME_RDAP, INFRA_STATUS_TOOL_ERROR, None, detail, str(exc)), raw
        return InfraRecord(NAME_RDAP, INFRA_STATUS_RECEIVED, result, detail), raw
    # 그 외 상태(429·403·503 등)도 서버가 답한 것이라 응답 수신이며, 그 답의 어휘(HTTP 숫자)를 result에 적는다.
    if body is not None:
        if "errorCode" in body:
            detail["error_code"] = body["errorCode"]
        if "title" in body:
            detail["error_title"] = body["title"]
    return InfraRecord(NAME_RDAP, INFRA_STATUS_RECEIVED, f"HTTP {response.status_code}", detail), raw


def not_queried_rdap() -> InfraRecord:
    """호스트가 IP라 묻지 않았을 때의 기록 하나."""
    return InfraRecord(NAME_RDAP, INFRA_STATUS_NOT_QUERIED, reason=REASON_HOST_IS_IP)


def _pick_server(registrable_unit: str) -> str | None:
    # RFC 7484의 규칙대로 가장 긴 접미사부터 찾는다. IANA 표는 TLD뿐이지만 보완 목록의 두 마디 접미사도 같은 코드로 된다.
    labels = registrable_unit.rstrip(".").split(".")
    for start in range(len(labels)):
        server = _TABLE.get(".".join(labels[start:]))
        if server is not None:
            return server
    return None


def _detail(started: float, response: httpx.Response | None = None) -> dict:
    detail: dict = {"table_version": RDAP_TABLE_VERSION}
    if response is not None and response.history:
        detail["redirects"] = [str(hop.url) for hop in response.history] + [str(response.url)]
    detail["elapsed_s"] = round(time.perf_counter() - started, 3)
    return detail


def _http_text(response: httpx.Response) -> str:
    """상태 줄 + 받은 헤더(이름 대소문자 그대로) + 빈 줄 + 본문 — HTTP/1.1 메시지 꼴 한 덩이.
    바이트 원문은 httpx가 내주지 않으므로 파싱된 객체의 표준 표현으로 남긴다(DNS의 to_text()와 같은 선). 리다이렉트 중간 응답은 담지 않는다."""
    head = [f"{response.http_version} {response.status_code} {response.reason_phrase}"]
    head += [f"{name.decode('latin-1')}: {value.decode('latin-1')}" for name, value in response.headers.raw]
    return "\r\n".join(head) + "\r\n\r\n" + response.text


def _json_object(response: httpx.Response) -> dict | None:
    try:
        body = response.json()
    except ValueError:
        return None
    return body if isinstance(body, dict) else None


def _parse_domain(body: dict) -> dict:
    # RFC 9083의 자리에서 원문 그대로 꺼낸다. 응답에 없는 조각은 키를 만들지 않는다.
    # 배열 필드는 키가 없을 수도, null로 올 수도 있다(DENIC은 삭제 유예 도메인의 nameservers를 null로 준다). 둘 다 빈 것으로 본다.
    result: dict = {}
    for event in body.get("events") or []:
        key = _EVENT_KEYS.get(event.get("eventAction"))
        if key is not None and "eventDate" in event:
            result.setdefault(key, event["eventDate"])
    status = body.get("status")
    if isinstance(status, list):
        result["status"] = status
    nameservers = [ns["ldhName"] for ns in body.get("nameservers") or [] if "ldhName" in ns]
    if nameservers:
        result["nameservers"] = nameservers
    registrar = _registrar(body.get("entities") or [])
    if registrar is not None:
        result["registrar"] = registrar
    return result


def _registrar(entities: list | None) -> dict | None:
    for entity in entities or []:
        if "registrar" not in (entity.get("roles") or []):
            continue
        registrar: dict = {}
        # vCard의 fn이 등록대행사 이름. 없으면 handle이라도 남긴다.
        for item in (entity.get("vcardArray") or ["vcard", []])[1] or []:
            if item[0] == "fn":
                registrar["name"] = item[3]
                break
        if "name" not in registrar and "handle" in entity:
            registrar["name"] = entity["handle"]
        for public_id in entity.get("publicIds") or []:
            if public_id.get("type") == "IANA Registrar ID":
                registrar["iana_id"] = public_id.get("identifier")
                break
        return registrar
    return None


def _load_bootstrap(path: Path) -> tuple[str, dict[str, str]]:
    """IANA 표 → (publication, 접미사→기본 URL). 한 접미사에 URL이 여럿이면 https 첫 것."""
    data = json.loads(path.read_text(encoding="utf-8"))
    table: dict[str, str] = {}
    for suffixes, urls in data["services"]:
        chosen = next((url for url in urls if url.startswith("https://")), urls[0])
        for suffix in suffixes:
            table[suffix] = chosen
    return data["publication"], table


def _load_supplement(path: Path) -> tuple[str, dict[str, str]]:
    """보완 목록 → (판, 사용 중 구역의 접미사→서버). 후보 구역은 읽지 않는다. 키가 빠지면 KeyError가 그대로 나간다."""
    data = json.loads(path.read_text(encoding="utf-8"))
    version, active, _candidates = data["version"], data["active"], data["candidates"]
    for entry in active:
        _ = (entry["suffix"], entry["server"], entry["basis"], entry["listed_on"])
    return version, {entry["suffix"]: entry["server"] for entry in active}


_EVENT_KEYS: dict[str, str] = {"registration": "registration", "expiration": "expiration", "last changed": "last_changed"}

_BOOTSTRAP_VERSION: str
_SUPPLEMENT_VERSION: str
_BOOTSTRAP_VERSION, _TABLE = _load_bootstrap(BOOTSTRAP_PATH)
_SUPPLEMENT_VERSION, _supplement_table = _load_supplement(SUPPLEMENT_PATH)
# 보완 목록은 IANA 표에 없는 접미사만 메운다. 겹치면 IANA가 이긴다.
for _suffix, _server in _supplement_table.items():
    _TABLE.setdefault(_suffix, _server)

# 302를 따라가지 않으면 「저쪽에 물어라」가 답으로 남는다. Accept는 RFC 7480이 요구하는 헤더.
_CLIENT: httpx.Client = httpx.Client(follow_redirects=True, headers={"Accept": "application/rdap+json"})

RDAP_TABLE_VERSION: str = f"iana-rdap-bootstrap {_BOOTSTRAP_VERSION} + supplement {_SUPPLEMENT_VERSION}"
