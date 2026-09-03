"""Network·Script Injection·환경 분기 Raw Observation Builder."""

from typing import Any

from L3_SCANNER.utils.url import etld1, resolve_http_url
from .ast import behavior_observations, expression_text, member_path, walk
from .base import AnalyzerBase
from .models import Element, Eval


class ObservationMixin(AnalyzerBase):
    """표현식 분석 결과를 Signal이 소비할 구조화 이벤트로 변환한다."""

    def _record_network(
        self, node: dict[str, Any], api: str, arguments: list[Eval]
    ) -> None:
        """Network API 목적지와 payload에 도달한 Credential Source를 함께 기록한다.

        XMLHttpRequest ``open``처럼 목적지가 두 번째 인자인 API를 구분한다. 실제 요청은
        전송하지 않으며 request body나 Credential 값도 저장하지 않는다.
        """
        destination_index = 1 if api.endswith(".open") else 0
        destination = (
            arguments[destination_index].literal
            if len(arguments) > destination_index
            else None
        )
        destination_url = (
            resolve_http_url(destination, self.document_url)
            if isinstance(destination, str)
            else None
        )
        destination_domain = etld1(destination_url)
        document_domain = etld1(self.document_url)
        # 목적지 인자는 전송 payload가 아니므로 Source-Sink taint 수집에서 제외한다.
        payload_arguments = [
            value for index, value in enumerate(arguments) if index != destination_index
        ]
        taints = [taint for value in payload_arguments for taint in value.taints]
        event = self._base_event(node, "network")
        event.update(
            {
                "api": api,
                "destination_url": destination_url,
                "destination_etld1": destination_domain,
                "external": (
                    destination_domain != document_domain
                    if destination_domain is not None and document_domain is not None
                    else None
                ),
                "source_links": [
                    {
                        "source_event_id": taint.source_event_id,
                        "credential_type": taint.credential_type,
                        "field_id": taint.field_id,
                        "transformations": list(taint.transformations),
                    }
                    for taint in taints
                ],
            }
        )
        self.raw["network_requests"].append(event)

    def _record_script_injection(
        self, node: dict[str, Any], api: str, element: Element
    ) -> None:
        """동적으로 생성된 script 요소가 DOM에 삽입되는 구조를 기록한다."""
        event = self._base_event(node, "script_injection")
        event.update(
            {"api": api, "url": element.source_url, "domain": etld1(element.source_url)}
        )
        self.raw["script_injection"].append(event)

    def _record_branch(self, node: dict[str, Any]) -> None:
        """정책에 등록된 환경 속성이 조건에 사용된 분기만 기록한다.

        양쪽 branch는 실행 결과가 아니라 호출·대입 등의 정적 구조 요약이다. 실제로
        어떤 경로가 선택되는지는 이 계층에서 주장하지 않는다.
        """
        properties = sorted(
            {
                path
                for member in walk(node.get("test"))
                if member.get("type") == "MemberExpression"
                for path in [member_path(member)]
                if path
                and self.policy.anti_bot_properties
                and path in self.policy.anti_bot_properties
            }
        )
        if not properties:
            return
        event = self._base_event(node, "branch")
        event.update(
            {
                "properties": properties,
                "condition": expression_text(node.get("test"), self.source),
                "branches": [
                    {
                        "condition_result": True,
                        "observations": behavior_observations(node.get("consequent")),
                    },
                    {
                        "condition_result": False,
                        "observations": behavior_observations(node.get("alternate")),
                    },
                ],
            }
        )
        self.raw["branches"].append(event)

    def _record_conditional_branch(self, node: dict[str, Any]) -> None:
        """삼항 연산자를 if와 동일한 환경 분기 Evidence 형태로 변환한다."""
        self._record_branch(
            {
                **node,
                "consequent": node.get("consequent"),
                "alternate": node.get("alternate"),
            }
        )
