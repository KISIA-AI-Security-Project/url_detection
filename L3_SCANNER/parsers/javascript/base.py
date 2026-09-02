"""정적 JavaScript 분석의 공유 상태와 이벤트 provenance 기본 기능."""

from typing import Any, Iterable, Mapping

from L3_SCANNER.models.input import ScriptInput
from L3_SCANNER.policies.detection import DetectionPolicy
from .models import Element, Eval, Taint, unique_lineage, unique_taints


class AnalyzerBase:
    """Mixin이 공유하는 분석 문맥, 변수 상태, 이벤트 생성 규칙.

    ``origin='static'``을 모든 이벤트에 명시해 실제 런타임 관측으로 오인되지 않게
    한다. 변수 저장소는 제한적 데이터 흐름만 표현하며 JavaScript 의미 전체를
    에뮬레이션하지 않는다.
    """

    def __init__(
        self,
        *,
        raw: dict[str, Any],
        script: ScriptInput,
        source: str,
        document_url: str,
        policy: DetectionPolicy,
        credential_fields: dict[str, dict[str, Any]],
    ) -> None:
        """스크립트 하나에 대한 격리된 정적 분석 상태를 초기화한다."""
        self.raw = raw
        self.script = script
        self.source = source
        self.document_url = document_url
        self.policy = policy
        self.credential_fields = credential_fields
        self.variables: dict[str, Eval] = {}
        self._sequence = 0
        self._seen_environment: set[tuple[str, str]] = set()
        self._seen_credentials: set[tuple[str, str]] = set()

    def _event_id(self, node: Mapping[str, Any], kind: str) -> str:
        """Source 범위를 우선 사용해 재현 가능한 이벤트 식별자를 만든다."""
        span = node.get("range") or []
        if len(span) == 2:
            return f"{self.script.script_id}:{kind}:{span[0]}-{span[1]}"
        self._sequence += 1
        return f"{self.script.script_id}:{kind}:{self._sequence}"

    def _base_event(self, node: Mapping[str, Any], kind: str) -> dict[str, Any]:
        """모든 관측에 script/node/event 식별자와 정적 출처를 부여한다."""
        return {
            "event_id": self._event_id(node, kind),
            "node_id": self._event_id(node, "node"),
            "script_id": self.script.script_id,
            "origin": "static",
        }

    @staticmethod
    def _combine(values: Iterable[Eval]) -> Eval:
        """여러 하위 표현식의 구조적 흐름을 중복 없이 하나로 합친다."""
        taints: list[Taint] = []
        element: Element | None = None
        decode_lineage: list[dict[str, str]] = []
        for value in values:
            taints.extend(value.taints)
            element = element or value.element
            decode_lineage.extend(value.decode_lineage)
        return Eval(
            taints=unique_taints(taints),
            element=element,
            decode_lineage=unique_lineage(decode_lineage),
        )

    @staticmethod
    def _with_transformation(value: Eval, method: str) -> Eval:
        """Credential taint마다 값 대신 적용된 변환 함수 이름만 추가한다."""
        return Eval(
            taints=[
                Taint(
                    credential_type=item.credential_type,
                    field_id=item.field_id,
                    source_event_id=item.source_event_id,
                    transformations=(*item.transformations, method),
                )
                for item in value.taints
            ],
            element=value.element,
            decode_lineage=list(value.decode_lineage),
        )

    # 아래 훅은 Statement/Expression/Observation Mixin이 구현한다. 기본 클래스에
    # 계약을 드러내어 순환 import 없이 각 책임을 조합할 수 있게 한다.
    def _process_statement(self, node: Any) -> None:
        """AST 문장을 순회하는 조합 훅."""
        raise NotImplementedError

    def _eval_expr(self, node: Any) -> Eval:
        """표현식의 제한적 정적 값을 계산하는 조합 훅."""
        raise NotImplementedError

    def _record_network(
        self, node: dict[str, Any], api: str, arguments: list[Eval]
    ) -> None:
        """Network Sink 이벤트를 기록하는 조합 훅."""
        raise NotImplementedError

    def _record_script_injection(
        self, node: dict[str, Any], api: str, element: Element
    ) -> None:
        """동적 Script 삽입 이벤트를 기록하는 조합 훅."""
        raise NotImplementedError

    def _record_branch(self, node: dict[str, Any]) -> None:
        """환경 기반 if 분기를 기록하는 조합 훅."""
        raise NotImplementedError

    def _record_conditional_branch(self, node: dict[str, Any]) -> None:
        """환경 기반 삼항 연산 분기를 기록하는 조합 훅."""
        raise NotImplementedError
