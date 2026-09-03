"""
그룹 A~F 판정 함수들이 공통으로 쓰는 결과 모델.

각 판정 함수는 URL 하나에 대해 AnalysisRecord 하나를 돌려준다.
"탐지됨"이든 "해당없음"이든 항상 레코드를 만든다 — 판정을 수행했다는 사실 자체가
증거이기 때문이다. (레코드가 없으면 "검사를 안 한 것"과 "검사했는데 정상인 것"을
사후에 구분할 수 없다.)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class DetectionStatus(str, Enum):
    """판정 결과 상태."""

    DETECTED = "확인함"      # 해당 패턴이 탐지됨
    NOT_APPLICABLE = "해당없음"  # 검사했으나 해당하지 않음 (정상이거나 검사 대상 자체가 아님)
    ERROR = "판정실패"        # 판정 도중 예외 발생 (registry의 try/except에서 생성)


@dataclass
class AnalysisRecord:
    """판정 1건의 결과."""

    name: str
    status: DetectionStatus
    # 탐지 근거. 항목마다 구조가 다르므로(문자열 하나일 수도, 중첩 dict일 수도) Any로 둔다.
    value: Any = None
    # 판정에 사용한 참조 목록의 버전. 목록이 바뀌면 같은 URL도 다르게 판정될 수 있으므로
    # 재현·감사를 위해 남긴다. 참조 목록을 쓰지 않는 항목(길이 검사 등)은 비워둔다.
    list_version: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """AnalysisRecord 저장 형식으로 변환."""
        record: dict[str, Any] = {
            "name": self.name,
            "value": self.value,
            "status": self.status.value,
        }
        if self.list_version:
            record["list_version"] = self.list_version
        return {"analysis_record": record}


def not_applicable(name: str, **kwargs: Any) -> AnalysisRecord:
    """'해당없음' 레코드를 만드는 단축 함수 (판정 함수마다 반복되는 코드를 줄인다)."""
    return AnalysisRecord(name=name, status=DetectionStatus.NOT_APPLICABLE, **kwargs)


def detected(name: str, value: Any, **kwargs: Any) -> AnalysisRecord:
    """'확인함' 레코드를 만드는 단축 함수."""
    return AnalysisRecord(
        name=name, status=DetectionStatus.DETECTED, value=value, **kwargs
    )


def failed(name: str, error: Exception) -> AnalysisRecord:
    """
    '판정실패' 레코드를 만드는 단축 함수. registry의 try/except에서 쓴다.

    판정 하나가 예외를 던져도 나머지는 계속 진행해야 하고, 실패했다는 사실도
    증거로 남아야 한다. 레코드가 없으면 "검사를 안 한 것"과 "검사하다 터진 것"을
    사후에 구분할 수 없다.

    예외 메시지를 그대로 싣지 않고 타입과 문자열만 남긴다. 스택 트레이스는
    로그로 가고, 레코드에는 사람이 원인을 짚을 최소한만 둔다.
    """
    return AnalysisRecord(
        name=name,
        status=DetectionStatus.ERROR,
        value={"error_type": type(error).__name__, "error_message": str(error)},
    )