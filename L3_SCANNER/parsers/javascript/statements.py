"""제한형 정적 분석을 위한 ESTree 문장과 제어 흐름 순회."""

from typing import Any
from copy import deepcopy
from .models import Eval

from .ast import identifier_name
from .base import AnalyzerBase


class StatementMixin(AnalyzerBase):
    """주요 Statement를 순회하며 표현식 평가와 분기 관측을 호출한다."""

    def _process_statement(self, node: Any) -> None:
        """지원 문장을 처리하고 함수·분기 범위에서 변수 상태를 보수적으로 관리한다."""
        if not isinstance(node, dict):
            return
        self._visit()
        kind = node.get("type")
        if kind in {"Program", "BlockStatement"}:
            for child in node.get("body", []):
                if child.get("type") == "FunctionDeclaration":
                    name = identifier_name(child.get("id"))
                    if name: self._register_function(name, child)
            depth=len(self.control_context)
            try:
                for child in node.get("body", []):
                    self._process_statement(child)
                    if child.get('type') in {'ReturnStatement','ThrowStatement','BreakStatement','ContinueStatement'}:
                        self.control_context.append({'construct':'preceding_block_exit',
                            'statement':child['type'], 'path_state':'after_direct_exit_in_same_block',
                            'scope':'Lexically follows a direct exit in this block; no runtime execution observed'})
            finally:
                del self.control_context[depth:]
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
            self._limitation('function_return_value_unresolved' if kind=='ReturnStatement' else 'throw_control_flow_unresolved',
                'Exit statement retained; full inter-block exit and return-value propagation are not modeled',node)
        elif kind == "IfStatement":
            self._record_branch(node)
            self._eval_expr(node.get("test"))
            # 양쪽 분기를 정적으로 모두 관찰하되, 이후에는 두 경로 모두에서 동일하게
            # 유지된 기존 변수만 남겨 한 경로의 값을 확정 실행 결과처럼 쓰지 않는다.
            original = deepcopy(self.variables)
            self._conditional_body(node, "consequent", True)
            consequent = deepcopy(self.variables)
            self.variables = deepcopy(original)
            self._conditional_body(node, "alternate", False)
            alternate = self.variables
            self.variables = {}
            for key in consequent.keys() | alternate.keys():
                left, right = consequent.get(key, Eval()), alternate.get(key, Eval())
                if left == right:
                    self.variables[key] = left
                else:
                    value = self._combine([left, right])
                    value.possible_literals = list(dict.fromkeys(v for x in [left, right]
                        for v in ([x.literal] if isinstance(x.literal, (str,int,float,bool)) else x.possible_literals)))[:8]
                    self.variables[key] = value
                    self._limitation("conditional_value_unresolved", "Branches produce different values; candidate values retained, selected branch unobserved")
        elif kind in {"WhileStatement", "DoWhileStatement", "ForStatement"}:
            self._eval_expr(node.get("init"))
            self._eval_expr(node.get("test"))
            self._eval_expr(node.get("update"))
            self._loop_body(node)
        elif kind in {"ForInStatement", "ForOfStatement"}:
            self._eval_expr(node.get("right"))
            self._loop_body(node)
        elif kind in {
            "FunctionDeclaration",
            "FunctionExpression",
            "ArrowFunctionExpression",
        }:
            name = identifier_name(node.get("id"))
            if name:
                self._register_function(name, node)
                # 선언 본문도 정적으로 관찰하되 실제 호출·인자는 확인하지 않았다.
                self._call_function(self.functions[name], None, node, declaration=True)
            else:
                self._process_function(node)
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

    def _conditional_body(self, node, part, required):
        """Keep the enclosing condition on events, even when both arms are inspected.

        Only a Boolean literal is evaluated here. Unknown/dynamic conditions are
        recorded, not executed or converted into an observed path.
        """
        test = node.get('test') or {}
        span = test.get('range') or [0, 0]
        literal = test.get('value') if test.get('type') == 'Literal' else None
        known = type(literal) is bool
        condition = self.source[span[0]:span[1]]
        self.control_context.append({
            'construct': 'if', 'condition': condition[:1200],
            'condition_truncated': len(condition) > 1200,
            'required_value': required,
            'literal_value': literal if known else None,
            'path_state': ('literal_allows_arm' if literal == required else 'literal_excludes_arm') if known else 'not_evaluated',
            'scope': 'Enclosing static condition; not an observed execution path',
        })
        if not known:
            self._limitation('branch_reachability_not_evaluated',
                'Condition retained; dynamic path feasibility was not evaluated', test)
        try:
            self._process_statement(node.get(part))
        finally:
            self.control_context.pop()

    def _loop_body(self,node):
        test=node.get('test') or node.get('right') or {}
        span=test.get('range') or [0,0]
        condition=self.source[span[0]:span[1]]
        value=test.get('value') if test.get('type')=='Literal' else None
        excluded=(node.get('type') in {'WhileStatement','ForStatement'} and value is False)
        self.control_context.append({'construct':node.get('type'),
            'condition':condition[:1200],'condition_truncated':len(condition)>1200,
            'path_state':'literal_excludes_body' if excluded else 'iteration_not_evaluated',
            'scope':'Static loop-body inspection; iteration counts and full loop control flow are not modeled'})
        self._limitation('loop_execution_not_modeled',
            'Loop condition retained; loop iterations and full control flow are not evaluated',node)
        try:self._process_statement(node.get('body'))
        finally:self.control_context.pop()

    def _register_function(self, name, node):
        self.functions[name] = {'node':node,'script':self.script,'source':self.source}

    def _call_function(self, binding, arguments, call_node, declaration=False):
        saved_script, saved_source = self.script, self.source
        span=call_node.get('range') or [0,0]
        self.call_context.append(('declaration' if declaration else 'call')+f'-{self.script.script_id}-{span[0]}-{span[1]}')
        self.script, self.source=binding['script'],binding['source']
        try: return self._process_function(binding['node'], arguments)
        finally:
            self.script, self.source=saved_script,saved_source
            self.call_context.pop()

    def _process_function(self, node, arguments=None):
        """정적으로 연결된 직접 호출만 인자를 묶는다. 콜백 인자는 미확정이다."""
        if self.call_depth >= 3:
            self._limitation("function_call_depth_limit", "Static function call depth exceeded")
            return Eval()
        saved, saved_functions = self.variables, dict(self.functions)
        self.variables = deepcopy(saved)
        for index, param in enumerate(node.get("params", [])):
            name = identifier_name(param)
            if name:
                self.variables[name] = arguments[index] if arguments is not None and index < len(arguments) else Eval()
        if arguments is None and node.get("params"):
            self._limitation("callback_parameters_unresolved", "Callback arguments and invocation unobserved; parameters do not inherit outer bindings")
        self.call_depth += 1
        try:
            body = node.get("body") or {}
            if body.get("type", "").endswith("Statement"):
                self._process_statement(body)
            else:
                self._eval_expr(body)
        finally:
            self.call_depth -= 1
            self.variables, self.functions = saved, saved_functions
        return Eval()

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
