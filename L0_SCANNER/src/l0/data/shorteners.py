"""
그룹 C-3(단축 URL) 판정에 쓰는 단축 서비스 도메인 목록 로더.

[구조] 이 모듈은 목록을 들고 있지 않는다. 옆의 shorteners.json을 읽을 뿐이다.
목록 본체가 파이썬 파일이 아닌 이유는, 동기화 배치(scripts/sync_shorteners.py)가
주 1회 덮어쓰는 데이터이기 때문이다. 코드 파일을 배치가 덮어쓰면 주석과 구조가
매번 날아간다. 데이터는 JSON, 로직은 파이썬으로 분리한다.

[런타임에 네트워크를 타지 않는다]
목록은 배포 시점에 이미 파일로 존재해야 한다. 판정 중에 GitHub을 조회하면
(1) L0의 무접속 원칙 위반 (2) Lambda VPC에서 아웃바운드 차단 시 실패
(3) 콜드 스타트마다 수백 ms 지연 (4) 외부 서비스 장애가 곧 우리 서비스 장애다.

[파일이 없거나 깨졌을 때]
예외를 던지지 않는다. import 시점에 터지면 L0 전체가 죽어 그룹 A·B 판정까지
잃는다. 대신 빈 집합으로 두고 버전을 "unavailable"로 남긴다. 그러면 C-3만
조용히 "해당없음"이 되는 것이 아니라, 모든 레코드의 list_version에
"unavailable"이 찍혀 장애가 드러난다.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_JSON_PATH = Path(__file__).with_name("shorteners.json")

# 목록을 읽지 못했을 때 list_version에 실리는 값.
# 빈 목록 때문에 모든 URL이 "해당없음"으로 나가는 상황을 레코드만 보고
# 알아챌 수 있어야 한다.
_UNAVAILABLE = "unavailable"


def _load() -> tuple[frozenset[str], str]:
    """shorteners.json을 읽어 (도메인 집합, 버전)을 돌려준다."""
    try:
        payload = json.loads(_JSON_PATH.read_text(encoding="utf-8"))
        domains = frozenset(d.lower() for d in payload["domains"])
        version = str(payload["version"])
    except (OSError, ValueError, KeyError, TypeError) as e:
        logger.error(
            "shorteners.json 로드 실패 — C-3가 무력화된다. "
            "scripts/sync_shorteners.py를 실행할 것. (%s: %s)",
            type(e).__name__,
            e,
        )
        return frozenset(), _UNAVAILABLE

    if not domains:
        logger.error("shorteners.json이 비어 있다 — C-3가 무력화된다.")
        return frozenset(), _UNAVAILABLE

    return domains, version


# 모듈 로드 시 1회만 읽는다. 요청마다 파일을 다시 열 이유가 없다.
SHORTENER_DOMAINS, SHORTENERS_VERSION = _load()
