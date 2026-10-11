"""Bounded syntactic request relationships, produced from the existing AST.

No source execution or whole-script quotation. Unsupported callback/data-flow
forms remain unconnected; the consumer must not infer them from nearby source.
"""
from copy import deepcopy
from .ast import identifier_name, walk


FUNCTIONS = {'FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression'}
CONTROLS = {'preventDefault', 'stopPropagation', 'stopImmediatePropagation'}


def member_path(node):
    """Require a complete static receiver; never fall back to a suffix."""
    if not isinstance(node, dict):
        return None
    if node.get('type') == 'Identifier':
        return node.get('name')
    if node.get('type') != 'MemberExpression':
        return None
    base = member_path(node.get('object'))
    prop = node.get('property', {})
    name = prop.get('value') if node.get('computed') and prop.get('type') == 'Literal' else identifier_name(prop) if not node.get('computed') else None
    return base + '.' + name if base and isinstance(name, str) else None


def _call(node, path):
    return node.get('type') == 'CallExpression' and member_path(node.get('callee')) == path


def _string(node):
    if node.get('type') == 'Literal' and isinstance(node.get('value'), str):
        return node['value']
    if node.get('type') == 'BinaryExpression' and node.get('operator') == '+':
        left, right = _string(node.get('left', {})), _string(node.get('right', {}))
        if left is not None and right is not None:
            return left + right
    return None


def _fragment(node, source, **values):
    lo, hi = node['range']
    return {**values, 'source_range': [lo, hi], 'source_excerpt': source[lo:hi]}


def _has_name(pattern, name):
    return any(identifier_name(node) == name for node in walk(pattern))


def _binds_or_writes(tree, name, *, ignore_param=None, ignore_declaration=None):
    for node in walk(tree):
        kind = node.get('type')
        if kind == 'VariableDeclarator' and node is not ignore_declaration and _has_name(node.get('id'), name):
            return True
        if kind in FUNCTIONS:
            if identifier_name(node.get('id')) == name:
                return True
            if node is not ignore_param and any(_has_name(p, name) for p in node.get('params', [])):
                return True
        if kind in {'AssignmentExpression', 'UpdateExpression'}:
            target = node.get('left') or node.get('argument')
            if _has_name(target, name) or (member_path(target) or '').startswith(name + '.'):
                return True
        if kind == 'CatchClause' and _has_name(node.get('param'), name):
            return True
    return False


def _callback(call):
    args = call.get('arguments', [])
    if len(args) != 1 or args[0].get('type') not in FUNCTIONS - {'FunctionDeclaration'}:
        return None
    fn = args[0]
    if fn.get('async') or fn.get('generator') or len(fn.get('params', [])) != 1:
        return None
    return fn if identifier_name(fn['params'][0]) else None


def _then(node, parents):
    member = parents.get(id(node), {})
    call = parents.get(id(member), {})
    if (member.get('type') == 'MemberExpression' and member.get('object') is node
            and not member.get('computed') and identifier_name(member.get('property')) == 'then'
            and call.get('type') == 'CallExpression' and call.get('callee') is member):
        return call
    return None


def _response_flow(node, parents, tree, source, bound):
    first = _then(node, parents)
    if not first:
        return None, False
    second = _then(first, parents)
    read_fn, write_fn = _callback(first), _callback(second or {})
    if not read_fn or not write_fn or bound(tree, 'fetch') or bound(tree, 'document'):
        return None, True
    read_name, write_name = identifier_name(read_fn['params'][0]), identifier_name(write_fn['params'][0])
    if (bound(read_fn, read_name, ignore_param=read_fn)
            or bound(write_fn, write_name, ignore_param=write_fn)):
        return None, True
    read = read_fn.get('body', {})
    if read.get('type') == 'BlockStatement':
        rows = read.get('body', [])
        read = rows[0].get('argument', {}) if len(rows) == 1 and rows[0].get('type') == 'ReturnStatement' else {}
    if not _call(read, read_name + '.text') or read.get('arguments'):
        return None, True
    body = write_fn.get('body', {})
    rows = body.get('body', []) if body.get('type') == 'BlockStatement' else [{'type': 'ExpressionStatement', 'expression': body}]
    calls = []
    for statement in rows:
        call = statement.get('expression', {}) if statement.get('type') == 'ExpressionStatement' else {}
        path = member_path(call.get('callee'))
        if call.get('type') != 'CallExpression' or path not in {'document.open', 'document.write', 'document.close'}:
            return None, True
        args = call.get('arguments', [])
        if path == 'document.write':
            if len(args) != 1 or identifier_name(args[0]) != write_name:
                return None, True
        elif args:
            return None, True
        calls.append(call)
    if [member_path(c.get('callee')) for c in calls] not in [['document.write'], ['document.open', 'document.write', 'document.close']]:
        return None, True
    return {'kind': 'fetch_text_to_document_write',
            'read': _fragment(read, source, api=read_name + '.text'),
            'writes': [_fragment(c, source, api=member_path(c['callee'])) for c in calls],
            'read_parameter': read_name, 'write_parameter': write_name,
            'chain_source_range': list(second['range'])}, False


def enrich_request_context(raw, script, tree):
    """Attach occurrence-bound relationships; the raw source remains unchanged."""
    events = [e for e in raw.get('network_requests', [])
              if e.get('script_id') == script.script_id and e.get('api') == 'fetch']
    if not events:
        return
    binding_cache, context_cache = {}, {}
    def bound(scope, name, **ignored):
        key = (id(scope), name, tuple((k, id(v)) for k, v in sorted(ignored.items())))
        if key not in binding_cache:
            binding_cache[key] = _binds_or_writes(scope, name, **ignored)
        return binding_cache[key]
    parents, by_range = {}, {}
    for node in walk(tree):
        if node.get('type') == 'CallExpression':
            by_range[tuple(node.get('range', []))] = node
        for value in node.values():
            for child in value if isinstance(value, list) else [value]:
                if isinstance(child, dict) and child.get('type'):
                    parents[id(child)] = node
    for event in events:
        span = tuple(event.get('source_range', []))
        if span in context_cache:
            if context_cache[span]:
                event['request_context'] = deepcopy(context_cache[span])
            continue
        node = by_range.get(span)
        if not node or not _call(node, 'fetch'):
            continue
        context = {'schema_version': 'request-context-1', 'execution_observed': False}
        scope = node
        while id(scope) in parents and scope.get('type') != 'WithStatement':
            scope = parents[id(scope)]
        if scope.get('type') == 'WithStatement':
            context['binding_scope_unresolved'] = True
            event['request_context'] = context
            context_cache[span] = context
            continue
        flow, unresolved = _response_flow(node, parents, tree, script.source, bound)
        if flow:
            context['response_flow'] = flow
        elif unresolved:
            context['response_flow_unresolved'] = True
        ancestors, current = [], node
        while id(current) in parents:
            current = parents[id(current)]
            ancestors.append(current)
            if current.get('type') in FUNCTIONS:
                break
        fn = ancestors[-1] if ancestors and ancestors[-1].get('type') in FUNCTIONS else None
        registration = parents.get(id(fn), {}) if fn else {}
        args = registration.get('arguments', [])
        api = member_path(registration.get('callee'))
        if (fn and registration.get('type') == 'CallExpression' and api in {'document.addEventListener', 'window.addEventListener'}
                and len(args) in {2, 3} and args[1] is fn and _string(args[0]) is not None
                and len(fn.get('params', [])) == 1 and identifier_name(fn['params'][0])
                and not bound(tree, api.split('.')[0])):
            param = identifier_name(fn['params'][0])
            if not bound(fn, param, ignore_param=fn):
                context['registration'] = _fragment(args[0], script.source, api=api, event_type=_string(args[0]), parameter=param)
                # Bind only a direct const declaration to an actual enclosing
                # identifier condition; other aliases/reassignments stay unknown.
                conditions = [a for a in ancestors if a.get('type') == 'IfStatement' and identifier_name(a.get('test'))]
                direct = fn.get('body', {}).get('body', [])
                for condition in conditions:
                    name = identifier_name(condition['test'])
                    for statement in direct:
                        if statement.get('type') != 'VariableDeclaration' or statement.get('kind') != 'const' or statement['range'][1] > condition['range'][0]:
                            continue
                        for declaration in statement.get('declarations', []):
                            init = declaration.get('init') or {}
                            values = init.get('arguments', [])
                            if (identifier_name(declaration.get('id')) == name and _call(init, param + '.target.closest')
                                    and len(values) == 1 and _string(values[0]) is not None
                                    and not bound(fn, name, ignore_declaration=declaration)):
                                context['condition_binding'] = _fragment(declaration, script.source, identifier=name, selector=_string(values[0]))
                # Only direct earlier statements in the very same block are
                # scoped together. Different branches/nested functions do not join.
                statement = next((a for a in ancestors if a.get('type') == 'ExpressionStatement'), None)
                block = parents.get(id(statement), {}) if statement else {}
                controls = []
                for previous in block.get('body', []) if block.get('type') == 'BlockStatement' else []:
                    if previous is statement:
                        break
                    call = previous.get('expression', {}) if previous.get('type') == 'ExpressionStatement' else {}
                    path = member_path(call.get('callee'))
                    if (call.get('type') == 'CallExpression' and path in {param + '.' + method for method in CONTROLS}
                            and not call.get('arguments')):
                        controls.append(_fragment(call, script.source, api=path))
                if controls:
                    context['event_controls'] = controls
        if len(context) > 2:
            event['request_context'] = context
            context_cache[span] = context
        else:
            context_cache[span] = None
