"""표현식 정적 평가와 스크립트 내부 Credential taint 전파.

이 모듈은 JavaScript를 실행하지 않는다. 제한된 리터럴·DOM lookup·변수 대입을 따라
민감 값 자체가 아닌 Source 식별자와 변환 계보만 Network Sink까지 전달한다.
"""

from typing import Any
from copy import deepcopy
from urllib.parse import urlsplit

from L3_SCANNER.utils.url import resolve_http_url
from .ast import callee_path, identifier_name, matches_api, member_path, property_name
from .base import AnalyzerBase
from .models import Element, Eval, Taint


class ExpressionMixin(AnalyzerBase):
    """ESTree 표현식을 제한적으로 해석해 Raw 이벤트와 데이터 흐름을 만든다."""

    def _eval_expr(self, node: Any) -> Eval:
        """지원 구문의 구조적 값을 평가하고 알 수 없는 구문은 자식만 보수적으로 순회한다.

        반환 ``Eval``은 실제 실행 결과가 아니다. 정적 분석으로 확실히 연결할 수 있는
        리터럴, taint, 요소와 decode 계보만 포함한다.
        """
        if not isinstance(node, dict):
            return Eval()
        self._visit()
        kind = node.get("type")
        if kind == "Literal":
            return Eval(literal=node.get("value"), literal_known=True)
        if kind == "TemplateLiteral":
            return self._eval_template(node)
        if kind == "Identifier":
            name = str(node.get("name"))
            return self.variables.get(name, Eval(api=name) if name in {"fetch", "XMLHttpRequest", "navigator", "window", "globalThis", "document", "location"} else Eval())
        if kind in {"CallExpression", "NewExpression"}:
            return self._eval_call(node)
        if kind == "MemberExpression":
            return self._eval_member(node)
        if kind in {"AssignmentExpression", "AssignmentPattern"}:
            value = self._eval_expr(node.get("right"))
            self._assign(node.get("left"), value, node)
            return value
        if kind in {"BinaryExpression", "LogicalExpression"}:
            return self._eval_binary(node)
        if kind == 'UnaryExpression' and node.get('operator') == 'delete':
            target=node.get('argument') or {}
            if target.get('type') == 'MemberExpression':
                obj=self._eval_expr(target.get('object'))
                key=self._property_key(target)
                if obj.properties is not None:
                    if key is None:
                        obj.properties=None;obj.taints=[]
                        self._limitation('object_write_unresolved', 'Unknown delete key; previous object member relationships invalidated', node)
                    else:
                        obj.properties.pop(key,None)
                else:
                    self._limitation('object_write_unresolved', 'Delete target is not statically resolved', node)
            else:
                self._eval_expr(target)
            return Eval()
        if kind in {
            "UnaryExpression",
            "UpdateExpression",
            "AwaitExpression",
            "YieldExpression",
        }:
            return self._eval_expr(node.get("argument"))
        if kind == "ConditionalExpression":
            self._record_conditional_branch(node)
            self._eval_expr(node.get("test"))
            return self._combine(
                (
                    self._eval_expr(node.get("consequent")),
                    self._eval_expr(node.get("alternate")),
                )
            )
        if kind == "SequenceExpression":
            value = Eval()
            for item in node.get('expressions', []):
                value = self._eval_expr(item)
            return value
        if kind == "ArrayExpression":
            value=self._combine(self._eval_expr(item) for item in node.get('elements', []))
            value.container_kind='array'
            return value
        if kind == "ObjectExpression":
            properties = {}
            known = True
            for item in node.get('properties', []):
                key = item.get('key') or {}
                name = key.get('value') if key.get('type') == 'Literal' else key.get('name') if not item.get('computed') else None
                value = self._eval_expr(item.get('value') or item.get('argument'))
                if item.get('type') != 'Property' or name is None or item.get('kind', 'init') != 'init':
                    known = False
                else:
                    properties[str(name)] = value
            result = self._combine(properties.values())
            result.properties = properties if known else None
            result.container_kind = 'object'
            if not known:
                result.taints = []
                self._limitation('object_structure_unresolved', 'Object spread, dynamic keys or accessors are not resolved; no member payload relationship asserted', node)
            return result
        if kind in {"FunctionExpression", "ArrowFunctionExpression"}:
            self._process_function(node)
            return Eval()
        return self._combine(
            self._eval_expr(item)
            for child in node.values()
            if isinstance(child, (dict, list))
            for item in (child if isinstance(child, list) else [child])
        )

    def _eval_template(self, node: dict[str, Any]) -> Eval:
        """Template literal의 삽입 표현식을 합치거나 정적 문자열을 복원한다."""
        expressions = node.get("expressions", [])
        if expressions:
            return self._combine(self._eval_expr(item) for item in expressions)
        cooked = "".join(
            str(part.get("value", {}).get("cooked", ""))
            for part in node.get("quasis", [])
        )
        return Eval(literal=cooked)

    def _eval_binary(self, node: dict[str, Any]) -> Eval:
        """문자열 덧셈은 정적으로 합치고 그 외에는 흐름 정보만 결합한다."""
        left = self._eval_expr(node.get("left"))
        right = self._eval_expr(node.get("right"))
        if not left.taints and not right.taints:
            if left.literal is not None and right.literal is not None:
                if node.get("operator") == "+":
                    if isinstance(left.literal, (int, float)) and isinstance(right.literal, (int, float)):
                        return Eval(literal=left.literal + right.literal)
                    if isinstance(left.literal, str) or isinstance(right.literal, str):
                        def js_string(v): return str(v).lower() if isinstance(v, bool) else str(v)
                        return Eval(literal=js_string(left.literal) + js_string(right.literal))
        value = self._combine((left, right))
        if node.get("operator") == "+" and isinstance(left.literal, str):
            value.url_prefix = left.literal
        elif node.get("operator") == "+" and left.url_prefix:
            value.url_prefix = left.url_prefix
        return value

    def _eval_member(self, node: dict[str, Any]) -> Eval:
        """환경 속성 읽기와 Credential 요소의 ``.value`` 접근을 관측한다."""
        path = self._resolve_api(node)
        obj = self._eval_expr(node.get("object"))
        property_value = self._property_key(node)
        if (
            path
            and self.policy.anti_bot_properties
            and path in self.policy.anti_bot_properties
        ):
            key = (path, self._event_id(node, "environment"))
            if key not in self._seen_environment:
                self._seen_environment.add(key)
                event = self._base_event(node, "environment")
                event.update({"property": path, "access_type": "read"})
                self.raw["environment_access"].append(event)
        if obj.properties is not None:
            if property_value is None:
                self._limitation('object_read_unresolved', 'Computed object member is unresolved; no value relationship asserted', node)
                return Eval()
            return obj.properties.get(property_value, Eval())
        if property_value == "value" and obj.element and obj.element.field and obj.element.field.get('credential_type'):
            return self._credential_value(node, obj.element.field)
        return Eval(taints=obj.current_taints(), element=obj.element, api=path)

    def _property_key(self, node):
        key = property_name(node)
        if key is None and node.get('computed'):
            value = self._eval_expr(node.get('property')).literal
            if isinstance(value, (str, int, float)): key = str(value)
        return key

    def _eval_call(self, node: dict[str, Any]) -> Eval:
        """정책 API 호출을 분류하고 인자에서 구조적 흐름을 전파한다.

        DOM lookup, 동적 실행, decode, network, redirect, script injection은 각각
        독립 Raw 컬렉션에 기록한다. 정적 API 참조만으로는 이 함수가 호출되지 않는다.
        """
        api = self._resolve_api(node.get("callee"))
        arguments = [self._eval_expr(arg) for arg in node.get("arguments", [])]
        if api in self.functions:
            return self._call_function(self.functions[api], arguments, node)
        if node.get("type") == "NewExpression" and api == "XMLHttpRequest":
            return Eval(api="XMLHttpRequestInstance")
        callee = node.get("callee") or {}
        if callee.get("type") == "MemberExpression":
            obj = self._eval_expr(callee.get("object"))
            method = property_name(callee)
            if obj.api == "XMLHttpRequestInstance":
                if method == "open":
                    obj.request.clear()
                    obj.request.update({"destination": arguments[1] if len(arguments)>1 else Eval(),
                                        "method":arguments[0].literal if arguments else None})
                elif method == "send" and self.policy.network_apis:
                    self._record_network(node,"XMLHttpRequest.send",[obj.request.get("destination", Eval()), *arguments])
                return Eval()
        call_result = self._combine(arguments)

        element = self._dom_lookup(api, arguments)
        if element is not None:
            call_result.element = element

        self._record_dynamic_execution(node, api, arguments)
        call_result = self._record_decode(node, api, call_result)

        if (
            api is not None
            and self.policy.network_apis
            and matches_api(api, self.policy.network_apis)
        ):
            self._record_network(node, api, arguments)

        if self.policy.redirect_apis and matches_api(api, self.policy.redirect_apis):
            destination = _first_literal(arguments)
            event = self._base_event(node, "redirect")
            event.update(
                {
                    "api": api,
                    "destination_url": (
                        resolve_http_url(destination, self.effective_base_url)
                        if isinstance(destination, str)
                        else None
                    ),
                }
            )
            self.raw["redirects"].append(event)

        if api and api.split(".")[-1] in {
            "appendChild",
            "append",
            "prepend",
            "insertBefore",
        }:
            for argument in arguments:
                if argument.element and argument.element.is_script:
                    self._record_script_injection(node, api, argument.element)

        if self._is_structural_transformation(api, call_result):
            call_result = self._with_transformation(
                call_result, api or "anonymous_call"
            )
        return call_result

    def _record_dynamic_execution(
        self, node: dict[str, Any], api: str | None, arguments: list[Eval]
    ) -> None:
        """설정된 동적 실행 API의 실제 Call/New AST와 입력 계보를 기록한다."""
        if not (
            self.policy.dynamic_execution_apis
            and matches_api(api, self.policy.dynamic_execution_apis)
        ):
            return
        event = self._base_event(node, "dynamic_execution")
        event.update(
            {
                "api": api,
                "invocation": (
                    "constructor" if node.get("type") == "NewExpression" else "call"
                ),
            }
        )
        if arguments and arguments[0].taints:
            event["input_links"] = [
                taint.source_event_id for taint in arguments[0].taints
            ]
        if arguments and arguments[0].decode_lineage:
            event["decode_links"] = list(arguments[0].decode_lineage)
        self.raw["dynamic_execution"].append(event)

    def _record_decode(
        self, node: dict[str, Any], api: str | None, value: Eval
    ) -> Eval:
        """설정된 decode 호출을 기록하고 후속 실행과 연결할 계보를 반환한다."""
        if not (
            api is not None
            and self.policy.decode_methods
            and matches_api(api, self.policy.decode_methods)
        ):
            return value
        event = self._base_event(node, "decode")
        event.update({"method": api})
        self.raw["decode_operations"].append(event)
        result = self._with_transformation(value, api)
        result.decode_lineage.append({"event_id": event["event_id"], "method": api})
        result.literal = None
        return result

    def _is_structural_transformation(self, api: str | None, value: Eval) -> bool:
        """taint를 유지해야 하는 일반 변환 호출인지 판단한다.

        Network와 동적 실행 API는 변환이 아니라 Sink이므로 변환 목록에 중복 기록하지
        않는다.
        """
        if not value.taints:
            return False
        is_network = bool(
            self.policy.network_apis and matches_api(api, self.policy.network_apis)
        )
        is_execution = bool(
            self.policy.dynamic_execution_apis
            and matches_api(api, self.policy.dynamic_execution_apis)
        )
        return not is_network and not is_execution

    def _dom_lookup(self, api: str | None, arguments: list[Eval]) -> Element | None:
        """지원하는 DOM 조회와 ``createElement('script')``를 구조적으로 추적한다.

        동적 selector나 복잡한 CSS selector는 억지로 추론하지 않고 빈 Element를
        반환해 잘못된 Credential 연결을 피한다.
        """
        lookup_apis = {
            "document.getElementById",
            "document.getElementsByName",
            "document.querySelector",
        }
        if api not in lookup_apis:
            if api == "document.createElement" and arguments:
                if arguments[0].literal == "script":
                    return Element(is_script=True)
            return None
        if not arguments or not isinstance(arguments[0].literal, str):
            return Element()
        selector = arguments[0].literal
        if api == "document.getElementById":
            return Element(field=self.credential_fields.get("id:"+selector))
        if api == "document.getElementsByName":
            # 컬렉션의 .value를 단일 필드처럼 취급하지 않는다. 인덱스 지원은 별도 한계다.
            self._limitation("dom_collection_unresolved", "getElementsByName returns a collection; element selection not modeled")
            return Element()
        if api == "document.querySelector":
            import re
            if re.fullmatch(r"#[a-zA-Z_][\w-]*", selector):
                return Element(field=self.credential_fields.get("id:"+selector[1:]))
            match = re.fullmatch(r"(?:input)?\[name=[\"']?([\w-]+)[\"']?\]", selector)
            if match:
                prefix = 'input-name:' if selector.startswith('input[') else 'name:'
                return Element(field=self.credential_fields.get(prefix+match.group(1)))
            # 'password'는 태그 선택자다. 같은 이름의 id에 연결할 근거가 없다.
            if re.fullmatch(r"[a-zA-Z][\w-]*", selector):
                return Element(field=self.credential_fields.get('tag:'+selector.lower()))
            self._limitation("css_selector_unresolved", "Unsupported CSS selector; no field relationship asserted")
        return Element()

    def _credential_value(self, node: dict[str, Any], field: dict[str, Any]) -> Eval:
        """Credential 값 읽기를 실제 값 없이 Source event와 taint로 기록한다."""
        event_id = self._event_id(node, "credential_access")
        key = (field["field_id"], event_id)
        if key not in self._seen_credentials:
            self._seen_credentials.add(key)
            event = self._base_event(node, "credential_access")
            event.update(
                {
                    "credential_type": field["credential_type"],
                    "field_id": field["field_id"],
                    "access_type": "value_read",
                }
            )
            self.raw["credential_access"].append(event)
            self.raw["dom_access"].append(dict(event))
            event_id = event["event_id"]
        return Eval(
            taints=[
                Taint(
                    credential_type=field["credential_type"],
                    field_id=field["field_id"],
                    source_event_id=event_id,
                )
            ]
        )

    def _assign(self, target: Any, value: Eval, node: dict[str, Any]) -> None:
        """변수 흐름, script.src, 정책 기반 redirect 대입을 제한적으로 추적한다."""
        name = identifier_name(target)
        if name:
            self.variables[name] = value
            return
        if isinstance(target, dict) and target.get('type') == 'MemberExpression':
            obj_value = self._eval_expr(target.get('object'))
            if obj_value.properties is not None:
                prop = self._property_key(target)
                if prop is None:
                    obj_value.properties = None
                    obj_value.taints = []
                    self._limitation('object_write_unresolved', 'Unknown object property write; previous member relationships invalidated', node)
                else:
                    obj_value.properties[prop] = value
                return
        path = member_path(target)
        if not path:
            return
        obj_name = (
            identifier_name(target.get("object")) if isinstance(target, dict) else None
        )
        if obj_name and obj_name in self.variables:
            element = self.variables[obj_name].element
            if element and element.is_script and path.endswith(".src"):
                if isinstance(value.literal, str):
                    element.source_url = resolve_http_url(
                        value.literal, self.effective_base_url
                    )
        path = self._resolve_api(target)
        if self.policy.redirect_apis and matches_api(path, self.policy.redirect_apis):
            event = self._base_event(node, "redirect")
            event.update(
                {
                    "api": path,
                    "destination_url": (
                        resolve_http_url(value.literal, self.effective_base_url)
                        if isinstance(value.literal, str)
                        else None
                    ),
                }
            )
            self.raw["redirects"].append(event)


def _first_literal(arguments: list[Eval]) -> Any:
    """첫 번째 인자의 정적 리터럴이 있으면 반환한다."""
    return arguments[0].literal if arguments else None
