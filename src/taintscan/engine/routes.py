"""Works out which parameters of a Flask view function come from the URL."""

import ast
import re

from taintscan.rules import SAFE_CONVERTERS

ROUTE_DECORATORS = {"route", "get", "post", "put", "patch", "delete"}
# Matches <name>, <path:name> and <string(length=2):name> in a route string.
URL_PARAM = re.compile(r"<(?:(?P<converter>\w+)(?:\(.*?\))?:)?(?P<name>\w+)>")


def tainted_params(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Parameters filled from the URL by a converter that allows arbitrary text."""
    args = func.args
    params = {a.arg for a in [*args.posonlyargs, *args.args, *args.kwonlyargs]}
    tainted: set[str] = set()
    for decorator in func.decorator_list:
        if not (
            isinstance(decorator, ast.Call)
            and isinstance(decorator.func, ast.Attribute)
            and decorator.func.attr in ROUTE_DECORATORS
        ):
            continue
        rule = decorator.args[0] if decorator.args else None
        if not (isinstance(rule, ast.Constant) and isinstance(rule.value, str)):
            tainted |= params  # route string is not a literal: assume the worst
            continue
        for match in URL_PARAM.finditer(rule.value):
            if (match["converter"] or "string") not in SAFE_CONVERTERS:
                tainted.add(match["name"])
    return tainted & params
