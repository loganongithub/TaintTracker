"""Works out which parameters of a Flask view function come from the URL."""

import ast
import re

from taintscan.finding import FROM_PATH_PARAM, FROM_URL_PARAM
from taintscan.rules import SAFE_CONVERTERS

ROUTE_DECORATORS = {"route", "get", "post", "put", "patch", "delete"}
# Matches <name>, <path:name> and <string(length=2):name> in a route string.
URL_PARAM = re.compile(r"<(?:(?P<converter>\w+)(?:\(.*?\))?:)?(?P<name>\w+)>")


def _literal_string(node: ast.AST) -> str | None:
    """The value of a string literal, including "a" + "b"; None for anything else."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _literal_string(node.left), _literal_string(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def is_route(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """True if the function is registered as a Flask view with a decorator."""
    return any(
        isinstance(decorator, ast.Call)
        and isinstance(decorator.func, ast.Attribute)
        and decorator.func.attr in ROUTE_DECORATORS
        for decorator in func.decorator_list
    )


def tainted_params(func: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, str]:
    """Parameters filled from the URL by a converter that allows arbitrary
    text, mapped to the kind of source they are."""
    args = func.args
    params = {a.arg for a in [*args.posonlyargs, *args.args, *args.kwonlyargs]}
    tainted: dict[str, str] = {}
    for decorator in func.decorator_list:
        if not (
            isinstance(decorator, ast.Call)
            and isinstance(decorator.func, ast.Attribute)
            and decorator.func.attr in ROUTE_DECORATORS
        ):
            continue
        rule = _literal_string(decorator.args[0]) if decorator.args else None
        if rule is None:
            tainted.update(dict.fromkeys(params, FROM_PATH_PARAM))  # not a literal: assume the worst
            continue
        for match in URL_PARAM.finditer(rule):
            converter = match["converter"] or "string"
            if converter not in SAFE_CONVERTERS:
                # <path:x> may contain "/"; a plain <x> may not.
                kind = FROM_PATH_PARAM if converter == "path" else FROM_URL_PARAM
                if tainted.get(match["name"]) != FROM_PATH_PARAM:
                    tainted[match["name"]] = kind
    return {name: kind for name, kind in tainted.items() if name in params}
