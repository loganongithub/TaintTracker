"""The records the engine keeps about a project: modules, functions, summaries."""

import ast
import re
from dataclasses import dataclass, field
from functools import cached_property

from taintscan.engine.names import ImportMap
from taintscan.engine.taint import CLEAN, Taint


# Names that suggest a function checks or cleans its input. The engine does
# not trust these (it cannot tell whether the check is any good); they only
# lower a finding's rank.
VALIDATOR_NAME = re.compile(
    r"valid|sanitiz|sanitis|secure|safe|allowed|trusted|is_child|within|inside|in_directory"
    r"|traversal|whitelist|allowlist",
    re.IGNORECASE,
)
# A narrower set: names that claim to make a path or URL safe. A value that
# has been through one of these is downgraded to weak taint (a low-confidence
# finding), never cleared. Deliberately excludes "allowed" and bare "valid":
# `allowed_file(name)` checks the extension and says nothing about "../".
SAFETY_NAME = re.compile(
    r"safe|secure|sanitiz|sanitis|trusted|is_child|within|inside|traversal"
    r"|validate_\w*(url|uri|path|host|file|dir)|(url|uri|path|host|file|dir)\w*_valid"
    r"|is_valid_\w*(url|uri|path|host|file|dir)",
    re.IGNORECASE,
)
# ...except these, which have "safe" in the name but hand back attacker content.
NOT_SAFETY_NAME = re.compile(
    r"safe_(load|dump|substitute|eval|str$)|mark_safe|safestring|^(load|dump|eval)", re.IGNORECASE
)
# Code that is not part of the running application.
TEST_CODE = re.compile(r"(^|[\\/])(tests?|testing)[\\/]|(^|[\\/])test_[^\\/]*$|_test\.py$|conftest\.py$")


PATH_RESOLVERS = {"realpath", "abspath", "normpath", "resolve"}


def _rejects(statement: ast.stmt) -> bool:
    """True for `raise ...`, `return` and `return None`."""
    if isinstance(statement, ast.Raise):
        return True
    if isinstance(statement, ast.Return):
        value = statement.value
        return value is None or (isinstance(value, ast.Constant) and value.value is None)
    return False


def claims_safety(name: str) -> bool:
    return bool(SAFETY_NAME.search(name)) and not NOT_SAFETY_NAME.search(name)

ADMIN_DECORATOR = re.compile(r"admin|permission|role|superuser|staff", re.IGNORECASE)
LOGIN_DECORATOR = re.compile(r"login|auth|jwt|token|session|protected|required", re.IGNORECASE)


def _last_name(node: ast.AST) -> str:
    """`login_required` from `@login_required`, `@x.login_required` or `@login_required(...)`."""
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Attribute):
        return node.attr
    return node.id if isinstance(node, ast.Name) else ""


@dataclass(frozen=True)
class SinkHit:
    """A sink call that some value reaches."""

    rule: str
    file: str
    line: int
    sink: str  # e.g. "requests.get"
    argument: str  # e.g. "url"
    weak: bool = False  # reached only by weak taint (see taint.py)
    depth: int = 0  # calls between here and where the data came in
    guarded: bool = False  # a validator-looking function is called along the way


@dataclass
class Summary:
    """Everything a caller needs to know about a function.

    returns: taint of the return value. Labels with a parameter origin
        mean "tainted if that argument is".
    param_sinks: parameter name -> sinks that parameter reaches inside
        the function (directly or through further calls).
    """

    returns: Taint = CLEAN
    param_sinks: dict[str, set[SinkHit]] = field(default_factory=dict)
    # When every `return` gives a tuple of the same length, the taint of each
    # position, so `data, name = f()` does not smear one onto the other.
    items: tuple[Taint, ...] | None = None


@dataclass
class Module:
    name: str  # dotted, e.g. "shop.views"
    file: str
    tree: ast.Module
    names: ImportMap
    # Module-level `NAME = "text"`, when NAME is assigned only once.
    constants: dict[str, str] = field(default_factory=dict)


@dataclass
class Class:
    name: str  # dotted, e.g. "shop.storage.Uploads"
    bases: list[str]  # dotted names of the base classes, as far as they resolve


@dataclass
class Function:
    name: str  # dotted, e.g. "shop.storage.read_upload"
    node: ast.FunctionDef | ast.AsyncFunctionDef
    module: Module
    owner: str | None = None  # dotted name of the class, if this is a method
    summary: Summary = field(default_factory=Summary)
    parent: int | None = None  # id() of the enclosing function's node, if nested

    @cached_property
    def guarded(self) -> bool:
        """True if the body looks like it validates something. Ranking only.

        Either it calls something whose name looks like a validator, or it
        has the shape of one: it resolves a path and has an `if` that
        rejects (raises, or returns nothing).
        """
        nodes = list(ast.walk(self.node))
        called = [_last_name(node) for node in nodes if isinstance(node, ast.Call)]
        if any(VALIDATOR_NAME.search(name) for name in called):
            return True
        resolves = any(name in PATH_RESOLVERS for name in called)
        rejects = any(
            isinstance(node, ast.If) and any(_rejects(statement) for statement in node.body)
            for node in nodes
        )
        return resolves and rejects

    @cached_property
    def auth(self) -> str:
        """ "admin", "login" or "none", judged from the decorator names."""
        names = [_last_name(decorator) for decorator in self.node.decorator_list]
        if any(ADMIN_DECORATOR.search(name) for name in names):
            return "admin"
        if any(LOGIN_DECORATOR.search(name) for name in names):
            return "login"
        return "none"

    @property
    def binds_receiver(self) -> bool:
        """True if the first parameter is self/cls, filled in by `obj.method()`."""
        if self.owner is None:
            return False
        decorators = {getattr(d, "id", None) for d in self.node.decorator_list}
        return "staticmethod" not in decorators

    @property
    def positional(self) -> list[str]:
        args = self.node.args
        return [a.arg for a in [*args.posonlyargs, *args.args]]

    @property
    def vararg(self) -> str | None:
        return self.node.args.vararg.arg if self.node.args.vararg else None

    @property
    def kwarg(self) -> str | None:
        return self.node.args.kwarg.arg if self.node.args.kwarg else None

    @property
    def params(self) -> list[str]:
        names = [*self.positional, *(a.arg for a in self.node.args.kwonlyargs)]
        return [*names, *filter(None, [self.vararg, self.kwarg])]
