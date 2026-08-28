"""제한형 정적 분석을 위한 ESTree 문장과 제어 흐름 순회."""

from typing import Any

from .ast import identifier_name
from .base import AnalyzerBase


class StatementMixin(AnalyzerBase):
    """주요 Statement를 순회하며 표현식 평가와 분기 관측을 호출한다."""

    def _process_statement(self, node: Any) -> None:
        """지원 문장을 처리하고 함수·분기 범위에서 변수 상태를 보수적으로 관리한다."""
        if not isinstance(node, dict):
            return
        kind = node.get("type")
        if kind in {"Program", "BlockStatement"}:
            for child in node.get("body", []):
                self._process_statement(child)
        elif kind == "VariableDeclaration":
            for declaration in node.get("declarations", []):
                name = identifier_name(declaration.get("id"))
                value = self._eval_expr(declaration.get("init"))
                if name:
                    self.variables[name] = value
        elif kind == "ExpressionStatement":
            self._eval_expr(node.get("expression"))
        elif kind in {"ReturnStatement", "ThrowStatement"}:
            self._eval_expr(node.get("argument"))
        elif kind == "IfStatement":
            self._record_branch(node)
            self._eval_expr(node.get("test"))
            # 양쪽 분기를 정적으로 모두 관찰하되, 이후에는 두 경로 모두에서 동일하게
            # 유지된 기존 변수만 남겨 한 경로의 값을 확정 실행 결과처럼 쓰지 않는다.
            original = dict(self.variables)
            self._process_statement(node.get("consequent"))
            consequent = dict(self.variables)
            self.variables = dict(original)
            self._process_statement(node.get("alternate"))
            self.variables = {
                key: value
                for key, value in original.items()
                if key in consequent and consequent[key] == value
            }
        elif kind in {"WhileStatement", "DoWhileStatement", "ForStatement"}:
            self._eval_expr(node.get("init"))
            self._eval_expr(node.get("test"))
            self._eval_expr(node.get("update"))
            self._process_statement(node.get("body"))
        elif kind in {"ForInStatement", "ForOfStatement"}:
            self._eval_expr(node.get("right"))
            self._process_statement(node.get("body"))
        elif kind in {
            "FunctionDeclaration",
            "FunctionExpression",
            "ArrowFunctionExpression",
        }:
            saved = dict(self.variables)
            self._process_statement(node.get("body"))
            self.variables = saved
        elif kind == "TryStatement":
            self._process_statement(node.get("block"))
            handler = node.get("handler") or {}
            self._process_statement(handler.get("body"))
            self._process_statement(node.get("finalizer"))
        elif kind == "SwitchStatement":
            self._eval_expr(node.get("discriminant"))
            for case in node.get("cases", []):
                self._eval_expr(case.get("test"))
                for child in case.get("consequent", []):
                    self._process_statement(child)
        elif kind == "LabeledStatement":
            self._process_statement(node.get("body"))
        else:
            self._process_unknown_children(node)

    def _process_unknown_children(self, node: dict[str, Any]) -> None:
        """전용 제어 흐름 모델이 없는 구문도 자식 관측은 잃지 않도록 순회한다.

        알 수 없는 구문의 실행 의미를 추측하지 않고 Statement와 Expression 자식을
        기존 처리기로 전달하는 데 그친다.
        """
        for child in node.values():
            if isinstance(child, dict):
                if child.get("type", "").endswith("Statement"):
                    self._process_statement(child)
                else:
                    self._eval_expr(child)
            elif isinstance(child, list):
                for item in child:
                    if isinstance(item, dict):
                        self._process_statement(item)
