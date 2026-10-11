"""Preserve literal data declarations without evaluating JavaScript.

Only top-level object/array assignments and JSON data blocks are supported.
These are source declarations, never final variable values or rendered content.
"""

import json
from copy import deepcopy
from hashlib import sha256
import re

from .ast import member_path
from L3_SCANNER.utils.url import resolve_http_url

MAX_DECLARATIONS = 128
MAX_NODES = 20_000
MAX_DEPTH = 32
_UNSUPPORTED = object()


def _literal(node, budget, depth=0):
    budget[0] -= 1
    if budget[0] < 0 or depth > MAX_DEPTH or not isinstance(node, dict):
        return _UNSUPPORTED
    kind = node.get("type")
    if kind == "Literal" and not node.get("regex"):
        value = node.get("value")
        return (
            value
            if value is None or type(value) in (str, int, float, bool)
            else _UNSUPPORTED
        )
    if kind == "UnaryExpression" and node.get("operator") == "-":
        value = _literal(node.get("argument"), budget, depth + 1)
        return -value if type(value) in (int, float) else _UNSUPPORTED
    if kind == "ArrayExpression":
        array_result = [
            _literal(child, budget, depth + 1) for child in node.get("elements", [])
        ]
        return (
            array_result
            if all(child is not _UNSUPPORTED for child in array_result)
            else _UNSUPPORTED
        )
    if kind == "ObjectExpression":
        result = {}
        for prop in node.get("properties", []):
            key = prop.get("key") or {}
            if (
                prop.get("type") != "Property"
                or prop.get("computed")
                or prop.get("method")
                or prop.get("kind", "init") != "init"
            ):
                return _UNSUPPORTED
            name = (
                key.get("name") if key.get("type") == "Identifier" else key.get("value")
            )
            if not isinstance(name, str) or name in result:
                return _UNSUPPORTED
            value = _literal(prop.get("value"), budget, depth + 1)
            if value is _UNSUPPORTED:
                return _UNSUPPORTED
            result[name] = value
        return result
    return _UNSUPPORTED


def _target(node):
    if not isinstance(node, dict):
        return None
    if node.get("type") == "Identifier":
        return node.get("name")
    return member_path(node) if node.get("type") == "MemberExpression" else None


def _append(raw, script, value, span, target, kind):
    rows = raw.setdefault("static_data", [])
    if len(rows) >= MAX_DECLARATIONS:
        if not any(
            e.get("code") == "static_data_declaration_limit" for e in raw["errors"]
        ):
            raw["errors"].append(
                {
                    "code": "static_data_declaration_limit",
                    "message": "Literal data declaration limit reached; full source is retained.",
                    "script_id": script.script_id,
                    "limit": MAX_DECLARATIONS,
                }
            )
        return
    lo, hi = span
    rows.append(
        {
            "script_id": script.script_id,
            "source_range": [lo, hi],
            "source_excerpt": script.source[lo:hi][:300],
            "origin": "static",
            "execution_observed": False,
            "declaration_kind": kind,
            "assignment_target": target,
            "value": value,
        }
    )


def collect_literal_declarations(raw, script, tree):
    """Reuse the already parsed AST; do not follow calls or conditional writes."""
    for statement in tree.get("body", []):
        candidates = []
        if statement.get("type") == "VariableDeclaration":
            candidates = [
                (child.get("id"), child.get("init"))
                for child in statement.get("declarations", [])
            ]
        elif statement.get("type") == "ExpressionStatement":
            expression = statement.get("expression") or {}
            if (
                expression.get("type") == "AssignmentExpression"
                and expression.get("operator") == "="
            ):
                candidates = [(expression.get("left"), expression.get("right"))]
        for target, node in candidates:
            name = _target(target)
            if (
                not name
                or not isinstance(node, dict)
                or node.get("type") not in {"ObjectExpression", "ArrayExpression"}
            ):
                continue
            value = _literal(node, [MAX_NODES])
            span = node.get("range")
            if value is not _UNSUPPORTED and isinstance(span, list) and len(span) == 2:
                _append(raw, script, value, span, name, "literal_assignment")


def collect_json_data(raw, script, max_bytes):
    if (
        not isinstance(script.source, str)
        or script.truncated
        or len(script.source.encode("utf-8", errors="replace")) > max_bytes
    ):
        return
    try:
        value = json.loads(script.source)
    except (ValueError, RecursionError):
        return
    stack = [(value, 0)]
    visited = 0
    while stack:
        child, depth = stack.pop()
        visited += 1
        if visited > MAX_NODES or depth > MAX_DEPTH:
            return
        if isinstance(child, dict):
            stack.extend((item, depth + 1) for item in child.values())
        elif isinstance(child, list):
            stack.extend((item, depth + 1) for item in child)
    if isinstance(value, (dict, list)):
        _append(raw, script, value, [0, len(script.source)], None, "json_data_block")


def _content_fields(value, document_url, path=""):
    """Record literal content roles and URL interpretation, never a click."""
    text_keys = {
        "title",
        "text",
        "label",
        "description",
        "headline",
        "message",
        "caption",
        "buttontext",
        "content",
    }
    address_keys = {
        "url",
        "href",
        "link",
        "action",
        "actionurl",
        "targeturl",
        "image",
        "src",
        "contenturl",
    }
    rows = []
    if isinstance(value, dict):
        declared_type = str(value.get("type") or "").lower()
        for key, child in value.items():
            token = str(key).replace("~", "~0").replace("/", "~1")
            child_path = path + "/" + token
            role = re.sub(r"[^a-z]", "", str(key).lower())
            if isinstance(child, str) and child.strip():
                address_role = role in address_keys or (
                    role == "content" and declared_type in {"image", "video", "audio"}
                )
                if address_role:
                    url = resolve_http_url(child, document_url or "")
                    rows.append(
                        {
                            "path": child_path,
                            "kind": "resource"
                            if declared_type in {"image", "video", "audio"}
                            or role in {"image", "src"}
                            else "address",
                            "value": child,
                            "resolved_url": url,
                            "declared_type": value.get("type"),
                        }
                    )
                elif role in text_keys and not child.lstrip().startswith(
                    ("http://", "https://")
                ):
                    rows.append(
                        {
                            "path": child_path,
                            "kind": "text",
                            "value": child,
                            "resolved_url": None,
                            "declared_type": value.get("type"),
                        }
                    )
            elif isinstance(child, (dict, list)):
                rows.extend(_content_fields(child, document_url, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            rows.extend(_content_fields(child, document_url, path + "/" + str(index)))
    return rows


def analyze_static_data(javascript_raw):
    """Carry declarations into native facts and normalized records unchanged."""
    declarations = javascript_raw.get("static_data") or []
    if not declarations:
        return []
    encoded = json.dumps(
        declarations, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()
    return [
        {
            "id": "L3-static-data",
            "kind": "static_literal_content_data",
            "scope": "Literal source declarations only; execution, rendered content and navigation unobserved.",
            "declarations": deepcopy(declarations),
            "content_fields": [
                _content_fields(
                    item["value"],
                    (javascript_raw.get("analysis") or {}).get("document_url"),
                )
                for item in declarations
            ],
            "source": {
                "pointer": "/javascript/static_data",
                "sha256": sha256(encoded).hexdigest(),
            },
        }
    ]
