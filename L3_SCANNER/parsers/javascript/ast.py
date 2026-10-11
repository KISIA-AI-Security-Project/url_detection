"""ESTree 파싱·순회·구문 이름 정규화를 위한 공통 도우미."""

from typing import Any, Iterable, Mapping

try:
    import esprima as esprima_module  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover - dependency error path
    esprima_module = None

esprima: Any = esprima_module


def parser_available() -> bool:
    """구조적 JavaScript 파서 의존성을 사용할 수 있는지 반환한다."""
    return esprima is not None


def _ast_to_dict(root: Any) -> dict[str, Any]:
    """Convert Esprima's AST with the same field rules and an explicit stack.

    The parser, ordered analysis and AST content do not change. A stack avoids
    adding a Python recursion limit to conversion. Unsupported generic values
    (including Python 3 re.Pattern) retain Esprima ToDictVisitor semantics.
    Actual cyclic Object input delegates to the original visitor.
    """
    from esprima.objects import Array, Object

    mapped_names = {"isAsync": "async", "allowAwait": "await"}
    holder: list[Any] = [None]
    active_objects: set[int] = set()
    leave = object()
    stack = [(root, holder, 0)]
    while stack:
        value, target, key = stack.pop()
        if target is leave:
            active_objects.remove(value)
            continue
        if isinstance(value, Object):
            identity = id(value)
            if identity in active_objects:
                return root.toDict()
            active_objects.add(identity)
            stack.append((identity, leave, None))
            value = value.__dict__
        value_type = type(value)
        if value_type is dict:
            converted: dict[str, Any] = {}
            children = []
            for field, item in value.items():
                if item is not None and not field.startswith("_"):
                    field = str(field)
                    mapped = mapped_names.get(field, field)
                    if mapped in converted:
                        return root.toDict()
                    if type(item) in (str, int, float, bool):
                        converted[mapped] = item
                    else:
                        converted[mapped] = None
                        children.append((item, converted, mapped))
            target[key] = converted
            stack.extend(reversed(children))
        elif value_type is list or value_type is Array:
            converted = [None] * len(value)
            target[key] = converted
            for index in range(len(value) - 1, -1, -1):
                item = value[index]
                if item is None or type(item) in (str, int, float, bool):
                    converted[index] = item
                else:
                    stack.append((item, converted, index))
        elif value_type.__name__ == "SRE_Pattern":
            target[key] = {}
        else:
            target[key] = value
    return holder[0]


def parse_source(source: str) -> dict[str, Any]:
    """Source를 위치·범위 정보가 포함된 ESTree 사전으로 변환한다.

    일반 script 문법을 먼저 시도하고 import/export 때문에 실패할 수 있는 경우 module
    문법으로 다시 시도한다. 코드를 실행하지 않으며 네트워크나 호스트에 접근하지 않는다.
    """
    if esprima is None:
        raise RuntimeError("The esprima dependency is unavailable")
    options = {"loc": True, "range": True, "tolerant": False}
    try:
        return _ast_to_dict(esprima.parseScript(source, options))
    except Exception:
        return _ast_to_dict(esprima.parseModule(source, options))


def walk(value: Any) -> Iterable[dict[str, Any]]:
    """중첩 ESTree에서 타입이 있는 모든 노드를 깊이 우선으로 순회한다."""
    if isinstance(value, dict):
        if "type" in value:
            yield value
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def identifier_name(node: Any) -> str | None:
    """Identifier 노드의 이름만 안전하게 반환한다."""
    if isinstance(node, dict) and node.get("type") == "Identifier":
        return str(node.get("name"))
    return None


def property_name(node: Mapping[str, Any]) -> str | None:
    """MemberExpression의 점 표기 또는 리터럴 속성명을 정규화한다."""
    prop = node.get("property")
    if not isinstance(prop, dict):
        return None
    if prop.get("type") == "Identifier" and not node.get("computed"):
        return str(prop.get("name"))
    if prop.get("type") == "Literal":
        return str(prop.get("value"))
    return None


def member_path(node: Any) -> str | None:
    """중첩 멤버 접근을 ``navigator.webdriver`` 같은 경로로 펼친다."""
    if not isinstance(node, dict):
        return None
    if node.get("type") == "Identifier":
        return str(node.get("name"))
    if node.get("type") in {"ThisExpression", "Super"}:
        return "this"
    if node.get("type") != "MemberExpression":
        return None
    obj = member_path(node.get("object"))
    prop = property_name(node)
    return f"{obj}.{prop}" if obj and prop else prop


def callee_path(node: Any) -> str | None:
    """호출 대상 AST를 정책 API 집합과 비교 가능한 문자열 경로로 바꾼다."""
    if not isinstance(node, dict):
        return None
    if node.get("type") == "Identifier":
        return str(node.get("name"))
    if node.get("type") == "MemberExpression":
        return member_path(node)
    if node.get("type") == "Import":
        return "import"
    return None


def matches_api(api: str | None, configured: Iterable[str]) -> bool:
    """정규화한 API가 명시적으로 설정된 정책 집합에 포함되는지 확인한다."""
    return api is not None and api in configured


def expression_text(node: Any, source: str) -> str:
    """증거용 조건식을 Source 범위에서 최대 240자로 제한해 추출한다."""
    if isinstance(node, dict):
        span = node.get("range") or []
        if len(span) == 2:
            return source[span[0] : span[1]][:240]
    return ""


def behavior_observations(node: Any) -> list[dict[str, str]]:
    """분기 내부의 호출·대입·return/throw를 실행 없이 구조적으로 요약한다."""
    observations: list[dict[str, str]] = []
    for item in walk(node):
        kind = item.get("type")
        if kind in {"CallExpression", "NewExpression"}:
            api = callee_path(item.get("callee"))
            if api:
                args = [arg.get("value") if arg.get("type") == "Literal" else {"type":arg.get("type")} for arg in item.get("arguments", [])]
                observations.append({"kind": "call", "target": api, "arguments":args})
        elif kind == "AssignmentExpression":
            target = member_path(item.get("left")) or identifier_name(item.get("left"))
            if target:
                value = item.get("right") or {}
                observations.append({"kind": "assignment", "target": target,
                                     "value":value.get("value") if value.get("type")=="Literal" else {"type":value.get("type")}})
        elif kind in {"ReturnStatement", "ThrowStatement"}:
            observations.append(
                {"kind": kind.removesuffix("Statement").lower(), "target": ""}
            )
    return observations
