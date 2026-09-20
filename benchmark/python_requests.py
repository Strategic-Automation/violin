"""Conservative HTTP request candidates from Python syntax, without executing it.

Resolve straight-line requests/session/httpx calls, urllib Request constructors,
import aliases, constant URLs and single-return HTTP wrappers. Never import or
execute the source. Dynamic control flow, formatting specifications, unknown
URLs and arbitrary helpers require explicit request/response proof instead.
Source observations are candidates, never execution evidence.
"""

from __future__ import annotations

import ast

from yarl import URL

_METHODS = {"get", "post", "put", "delete", "patch", "head", "options"}
_CLIENTS = {"requests", "session", "http", "httpx"}
_UNKNOWN = object()
_MAX_SOURCE = 256 * 1024


def _name(node: ast.AST, aliases: dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        return f"{_name(node.value, aliases)}.{node.attr}"
    return ""


def _constant(node: ast.AST | None, values: dict[str, object]) -> object:
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return values.get(node.id, _UNKNOWN)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _constant(node.left, values), _constant(node.right, values)
        if (
            isinstance(left, str)
            and isinstance(right, str)
            and len(left) + len(right) <= _MAX_SOURCE
        ):
            return left + right
    if isinstance(node, ast.JoinedStr):
        parts = []
        for part in node.values:
            if isinstance(part, ast.FormattedValue):
                if part.conversion != -1 or part.format_spec is not None:
                    return _UNKNOWN
                value = _constant(part.value, values)
                if type(value) not in {str, int, float, bool}:
                    return _UNKNOWN
                parts.append(str(value))
            elif isinstance(part, ast.Constant) and isinstance(part.value, str):
                parts.append(part.value)
            else:
                return _UNKNOWN
        return "".join(parts) if sum(map(len, parts)) <= _MAX_SOURCE else _UNKNOWN
    return _UNKNOWN


def _request(call: ast.Call, aliases: dict[str, str], values: dict[str, object]):
    if any(isinstance(arg, ast.Starred) for arg in call.args) or any(
        item.arg is None for item in call.keywords
    ):
        return _UNKNOWN
    keywords = {item.arg: item.value for item in call.keywords}
    if len(keywords) != len(call.keywords):
        return _UNKNOWN

    def argument(index, keyword):
        if len(call.args) > index:
            return _UNKNOWN if keyword in keywords else call.args[index]
        return keywords.get(keyword)

    name = _name(call.func, aliases)
    owner, _, verb = name.rpartition(".")
    if owner in _CLIENTS and verb in _METHODS:
        method, target = verb.upper(), argument(0, "url")
    elif owner in _CLIENTS and verb == "request":
        method, target = _constant(argument(0, "method"), values), argument(1, "url")
    elif name in {"Request", "urllib.request.Request"}:
        target = argument(0, "fullurl")
        method_node = argument(5, "method")
        method = _constant(method_node, values) if method_node is not None else None
        if method is None:
            data = argument(1, "data")
            value = _constant(data, values) if data is not None else None
            if value is _UNKNOWN:
                return _UNKNOWN
            method = "GET" if value is None else "POST"
    else:
        return None
    target = _constant(target, values)
    if not isinstance(method, str) or not isinstance(target, str):
        return _UNKNOWN
    method = method.upper()
    if method.lower() not in _METHODS or not target.startswith(("https://", "http://")):
        return _UNKNOWN
    try:
        url = URL(target)
        if url.host:
            return method, url
    except ValueError:
        return _UNKNOWN
    return _UNKNOWN


def _helper_request(call, helper, aliases, values):
    """Resolve a single-return HTTP wrapper at its call site, never execute it."""
    signature = helper.args
    if signature.vararg or signature.kwarg or signature.kwonlyargs:
        return _UNKNOWN
    if len(helper.body) != 1 or not isinstance(helper.body[0], ast.Return):
        return _UNKNOWN
    forwarded = helper.body[0].value
    if not isinstance(forwarded, ast.Call):
        return _UNKNOWN
    parameters = [arg.arg for arg in (*signature.posonlyargs, *signature.args)]
    if len(call.args) > len(parameters) or any(item.arg is None for item in call.keywords):
        return _UNKNOWN
    bound = dict(zip(parameters, call.args, strict=False))
    for item in call.keywords:
        if item.arg not in parameters or item.arg in bound:
            return _UNKNOWN
        bound[item.arg] = item.value
    if set(bound) != set(parameters):
        return _UNKNOWN
    local = {**values, **{key: _constant(value, values) for key, value in bound.items()}}
    local_aliases = {**aliases, **{key: "<parameter>" for key in parameters}}
    return _request(forwarded, local_aliases, local) or _UNKNOWN


def python_request_observations(source: str) -> list[tuple[str, URL]]:
    """Resolve bounded Python source; malformed/unsupported syntax earns no inference."""
    if len(source) > _MAX_SOURCE:
        return []
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return []
    try:
        return _extract_requests(tree)
    except RecursionError:
        return []


def _extract_requests(tree: ast.Module) -> list[tuple[str, URL]]:
    aliases: dict[str, str] = {}
    values: dict[str, object] = {}
    observations = []
    helpers: dict[str, ast.FunctionDef] = {}
    # Do not guess which branches, function bodies or comprehensions executed.
    for statement in tree.body:
        if isinstance(statement, ast.Import):
            for item in statement.names:
                helpers.pop(item.asname or item.name.split(".")[0], None)
                values.pop(item.asname or item.name.split(".")[0], None)
                aliases[item.asname or item.name.split(".")[0]] = (
                    item.name if item.asname else item.name.split(".")[0]
                )
        elif isinstance(statement, ast.ImportFrom):
            for item in statement.names:
                helpers.pop(item.asname or item.name, None)
                values.pop(item.asname or item.name, None)
                aliases[item.asname or item.name] = f"{statement.module}.{item.name}"
        elif isinstance(statement, ast.FunctionDef):
            if statement.decorator_list or statement.args.defaults or statement.args.kw_defaults:
                return []
            values.pop(statement.name, None)
            helpers[statement.name] = statement
            aliases[statement.name] = "<helper>"
        elif isinstance(statement, (ast.Expr, ast.Assign, ast.AnnAssign)):
            expression = statement.value
            # Nested call arguments are visited, but delayed/dynamic expressions are not inferred.
            nodes = list(ast.walk(expression)) if expression is not None else []
            if any(
                isinstance(
                    node, (ast.Lambda, ast.comprehension, ast.IfExp, ast.NamedExpr, ast.BoolOp)
                )
                for node in nodes
            ):
                return []
            for node in nodes:
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id in helpers:
                        result = _helper_request(node, helpers[node.func.id], aliases, values)
                    else:
                        result = _request(node, aliases, values)
                    if result is _UNKNOWN:
                        return []
                    if result is not None:
                        observations.append(result)
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                targets = (
                    statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                )
                value = _constant(expression, values)
                name = _name(expression, aliases) if expression is not None else ""
                if isinstance(expression, ast.Call) and _name(expression.func, aliases) in {
                    "requests.Session",
                    "httpx.Client",
                }:
                    name = "session"
                for target in targets:
                    if not isinstance(target, ast.Name):
                        return []
                    helpers.pop(target.id, None)
                    values[target.id] = value
                    aliases[target.id] = name or "<unresolved>"
        else:
            # Failing the whole source avoids attributing an ambiguous multi-call flow
            # to its one resolvable URL. Explicit structured proof still works.
            return []
    return list(dict.fromkeys(observations))
