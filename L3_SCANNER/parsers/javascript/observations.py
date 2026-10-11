"""Network·Script Injection·환경 분기 Raw Observation Builder."""

from typing import Any
from urllib.parse import urlsplit
from L3_SCANNER.utils.url import url_relations

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
        destination_value = (
            arguments[destination_index]
            if len(arguments) > destination_index
            else Eval()
        )
        destination_url = (
            resolve_http_url(destination, self.effective_base_url)
            if isinstance(destination, str)
            else None
        )
        prefix = destination_value.url_prefix
        prefix_url = (
            resolve_http_url(prefix, self.effective_base_url) if prefix else None
        )
        # 호스트 중간에 미확정 값이 있으면 외부 목적지를 확정할 수 없다.
        known_prefix = (
            prefix_url
            if prefix_url
            and ("?" in prefix_url or urlsplit(prefix_url).path.startswith("/"))
            else None
        )
        relation_url = destination_url or known_prefix
        destination_domain = etld1(relation_url)
        relations = url_relations(self.document_url, relation_url)
        taints = []
        positions = []
        configuration = "not_checked"
        payloads = [
            ("url" if i == destination_index else "request_argument", value)
            for i, value in enumerate(arguments)
        ]
        if api == "fetch":
            payloads = [("url", destination_value)]
            if len(arguments) > 1:
                options = arguments[1].properties
                if options is None:
                    self._limitation(
                        "fetch_options_unresolved",
                        "Fetch options fields are not statically resolved; no options payload relationship asserted",
                        node,
                    )
                else:
                    body = options.get("body")
                    method = options.get("method")
                    method_value = (
                        "GET"
                        if method is None
                        else method.literal.upper()
                        if isinstance(method.literal, str)
                        else None
                    )
                    known_null = (
                        body is not None and body.literal_known and body.literal is None
                    )
                    non_null = body is not None and (
                        body.literal is not None
                        or body.container_kind is not None
                        or bool(body.current_taints())
                    )
                    configuration = "no_known_method_body_conflict"
                    if method_value is None:
                        configuration = "method_unresolved"
                        self._limitation(
                            "fetch_request_unresolved",
                            "Fetch method is unresolved; request validity and payload relationship not asserted",
                            node,
                        )
                    elif (
                        method_value in ("GET", "HEAD")
                        and body is not None
                        and not known_null
                    ):
                        configuration = (
                            "invalid_get_head_body"
                            if non_null
                            else "body_nullability_unresolved"
                        )
                        self._limitation(
                            "fetch_request_unresolved",
                            "GET/HEAD Request cannot contain a non-null body; keep attempted destination and reads without asserting transmission",
                            node,
                        )
                    if body is not None:
                        if body.container_kind:
                            self._limitation(
                                "fetch_payload_conversion_unresolved",
                                "Object/array BodyInit conversion is not modeled; its internal fields are not asserted as transmitted",
                                node,
                            )
                        else:
                            payloads.append(("body", body))
                    headers = options.get("headers")
                    if headers is not None:
                        if headers.properties is None:
                            self._limitation(
                                "fetch_payload_conversion_unresolved",
                                "Only statically recorded header dictionaries are modeled",
                                node,
                            )
                        else:
                            for value in headers.properties.values():
                                if value.container_kind:
                                    self._limitation(
                                        "fetch_payload_conversion_unresolved",
                                        "Object/array header value conversion is not modeled",
                                        node,
                                    )
                                else:
                                    payloads.append(("headers", value))
                    if configuration in (
                        "method_unresolved",
                        "invalid_get_head_body",
                        "body_nullability_unresolved",
                    ):
                        payloads = []
        for position, value in payloads:
            if position == "url" and prefix and "#" in prefix:
                continue  # fragment는 HTTP 요청에 실리지 않는다.
            for taint in value.current_taints():
                taints.append(taint)
                positions.append(position)
        event = self._base_event(node, "network")
        event.update(
            {
                "api": api,
                "request_configuration": configuration,
                "destination_url": destination_url,
                "destination_etld1": destination_domain,
                "destination_prefix": known_prefix,
                "destination_candidates": [
                    resolve_http_url(v, self.effective_base_url)
                    for v in destination_value.possible_literals
                    if isinstance(v, str)
                ],
                "relations": relations,
                "external": None
                if relations["same_site_scope"] is None
                else not relations["same_site_scope"],
                "source_links": [
                    {
                        "source_event_id": taint.source_event_id,
                        "transmission_position": position,
                        "credential_type": taint.credential_type,
                        "field_id": taint.field_id,
                        "transformations": list(taint.transformations),
                    }
                    for taint, position in zip(taints, positions)
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
