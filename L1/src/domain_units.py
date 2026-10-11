import ipaddress
import json
from dataclasses import dataclass
from importlib.metadata import version as _package_version
from pathlib import Path
from publicsuffixlist import PSLFILE, PublicSuffixList

__all__ = [
    "DomainUnits",
    "compute_domain_units",
    "HOST_DOMAIN",
    "HOST_IPV4",
    "HOST_IPV6",
    "MATCH_PSL_PRIVATE",
    "MATCH_SUPPLEMENT",
    "MATCH_NONE",
    "MATCH_NOT_APPLICABLE",
    "SUPPLEMENT_PATH",
    "LIST_VERSION",
]

# 다섯 값에 들어가는 낱말. 검증 스크립트와 뒤 부품이 문자열을 직접 쓰지 않고 이 이름을 쓴다.
HOST_DOMAIN: str = "도메인"
HOST_IPV4: str = "IPv4"
HOST_IPV6: str = "IPv6"
MATCH_PSL_PRIVATE: str = "PSL 사설 구역"
MATCH_SUPPLEMENT: str = "보완 목록"
MATCH_NONE: str = "일치 없음"
MATCH_NOT_APPLICABLE: str = "해당 없음(IP)"

# 보완 목록 파일. 모듈 옆에 두어 L1/src/가 통째로 배포되면 따라간다.
SUPPLEMENT_PATH: Path = Path(__file__).with_name("psl_supplement.json")


@dataclass(frozen=True)
class DomainUnits:
    host_kind: str                  # HOST_DOMAIN / HOST_IPV4 / HOST_IPV6
    registrable_unit: str           # RDAP에 물어볼 등록 단위
    responsibility_boundary: str    # 책임 경계. urlscan이 이 값을 도메인 조건으로 받음
    platform_match: str             # 등록 단위와 책임 경계가 어느 목록에서 갈렸는지 / 일치하는지 / IP라서 해당없는지 -> MATCH_PSL_PRIVATE / MATCH_SUPPLEMENT / MATCH_NONE / MATCH_NOT_APPLICABLE
    list_version: str               # publicsuffixlist 판 + 보완 목록 판


def compute_domain_units(fqdn: str) -> DomainUnits:
    host_kind = _host_kind(fqdn)
    if host_kind != HOST_DOMAIN:
        return DomainUnits(host_kind, "", "", MATCH_NOT_APPLICABLE, LIST_VERSION)

    # privatesuffix는 이름 위에 사설 부분이 없으면 None을 돌려준다. 그때는 호스트 이름 자체가 그 단위다.
    registrable_unit = _PSL_ICANN.privatesuffix(fqdn) or fqdn
    responsibility_boundary = _PSL_MERGED.privatesuffix(fqdn) or fqdn
    return DomainUnits(host_kind, registrable_unit, responsibility_boundary, _matched_list(fqdn), LIST_VERSION)



# fqdn이 IP 주소면 HOST_IPV4/HOST_IPV6, 아니면 HOST_DOMAIN
def _host_kind(fqdn: str) -> str:
    # 입구 처리는 IPv6를 대괄호 포함으로 주는데 ipaddress는 대괄호를 받지 않는다. 판정할 때만 뗀다.
    bare = fqdn[1:-1] if fqdn.startswith("[") and fqdn.endswith("]") else fqdn
    try:
        address = ipaddress.ip_address(bare)
    except ValueError:
        return HOST_DOMAIN
    return HOST_IPV4 if address.version == 4 else HOST_IPV6


# 보완 목록 JSON → (판, 사용 중 구역의 도메인들). 후보 구역은 계산에 넣지 않는다.
def _load_supplement(path: Path) -> tuple[str, tuple[str, ...]]:
    """보완 목록 JSON → (판, 사용 중 구역의 도메인들). 후보 구역은 계산에 넣지 않는다."""
    data = json.loads(path.read_text(encoding="utf-8"))
    version, active, _candidates = data["version"], data["active"], data["candidates"]
    # 항목마다 근거·등재일이 데이터로 붙어 있어야 한다. 하나라도 없으면 KeyError가 그대로 나가 import가 실패한다.
    for entry in active:
        _ = (entry["domain"], entry["basis"], entry["listed_on"])
    return version, tuple(entry["domain"] for entry in active)


# 책임 경계가 어느 목록에 걸렸는지 — MATCH_SUPPLEMENT / MATCH_PSL_PRIVATE / MATCH_NONE.
def _matched_list(fqdn: str) -> str:
    # publicsuffix는 "걸린 접미사"를 돌려준다(privatesuffix는 그 위 한 마디). 목록을 더할 때마다
    # 걸린 접미사가 달라지는지로 출처를 가른다 — 규칙 문자열을 뒤지지 않아 와일드카드·예외 규칙에도 같은 방식이다.
    from_icann = _PSL_ICANN.publicsuffix(fqdn)
    from_psl = _PSL_FULL.publicsuffix(fqdn)
    from_merged = _PSL_MERGED.publicsuffix(fqdn)
    if from_merged != from_psl:
        return MATCH_SUPPLEMENT
    if from_psl != from_icann:
        return MATCH_PSL_PRIVATE
    return MATCH_NONE


# 아래 상수는 import 때 한 번만 만든다. PSL 16,400줄을 세 번 파싱하는 일을 호출마다 반복하지 않고,
# 보완 목록 파일이 깨졌으면 첫 호출이 아니라 import에서 드러나게 하기 위해서다.
_PSL_VERSION: str = _package_version("publicsuffixlist")  # 패키지에 __version__ 속성이 없어 메타데이터에서 읽는다
_SUPPLEMENT_VERSION: str
_SUPPLEMENT_DOMAINS: tuple[str, ...]
_SUPPLEMENT_VERSION, _SUPPLEMENT_DOMAINS = _load_supplement(SUPPLEMENT_PATH)

# 목록 객체 셋. (ㄱ)은 등록 단위, (ㄷ)은 책임 경계를 내고, (ㄴ)은 (ㄱ)·(ㄷ)과 비교해 어느 목록이 걸렸는지 가리는 데만 쓴다.
_PSL_ICANN: PublicSuffixList = PublicSuffixList(only_icann=True)
_PSL_FULL: PublicSuffixList = PublicSuffixList()
# (ㄷ) — 라이브러리가 기본 소스로 여는 그 파일(PSLFILE) 뒤에 보완 목록 줄을 이어 붙여 한 번에 파싱한다.
_PSL_MERGED: PublicSuffixList = PublicSuffixList(
    source=Path(PSLFILE).read_text(encoding="utf-8").splitlines() + list(_SUPPLEMENT_DOMAINS)
)

# 다섯째 값. 두 판을 한 문자열에 — 6칸 기록의 list_version 한 칸으로 그대로 들어간다.
LIST_VERSION: str = f"publicsuffixlist {_PSL_VERSION} + supplement {_SUPPLEMENT_VERSION}"
