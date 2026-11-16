"""Tracks taint through one function body, statement by statement.

The state is a dict: variable name -> taint (see taint.py). Statements
update the state in order. Expressions are evaluated to a taint by
eval(), which also checks every call it passes to see whether it is a
sink, and applies the callee's summary when the callee is a function
in the project.

While it runs, the tracker also fills in the Summary of the function it
is analyzing: what the function returns, and which parameters reach a
sink.
"""

import ast
import pathlib
import re
from dataclasses import replace

from taintscan.engine.model import Function, Module, SinkHit, Summary, _last_name, claims_safety
from taintscan.engine.routes import is_route
from taintscan.engine.taint import (
    CLEAN,
    NORMALIZED,
    Taint,
    base,
    from_source,
    is_real,
    is_weak,
    unmarked,
    weaken,
    weaken_rule,
    without,
)
from taintscan.finding import FROM_REQUEST, HIGH, LOW, PATH_TRAVERSAL, SSRF, Entry, Finding
from taintscan.rules import (
    CARRIERS,
    CLEANERS,
    EXIT_CALLS,
    KEY_ATTRIBUTES,
    NORMALIZERS,
    PATH_CLASSES,
    PATH_LAST_COMPONENT,
    RECEIVER_SINKS,
    REGEX_CHECKS,
    REQUEST_SOURCES,
    SANITIZERS,
    SINKS,
    STRIP_PATTERN,
    TEMPFILE_CALLS,
    TRAVERSAL_TEXT,
    UPLOAD_SINKS,
    URL_HOST_ATTRIBUTES,
    URL_PARSERS,
)

State = dict[str, Taint]

# A constant prefix like "https://api.example.com/" fixes the host.
# "https://api.example.com" (no slash) does not: "@evil.com" can follow it.
PINNED_HOST = re.compile(r"^https?://[^/@?#]+/")

# Methods of strings and paths. `template.format(x)` or `base.joinpath(x)`
# builds a new value out of x, so x's content survives. Other methods on
# an untainted object (`db.get_book(x)`, `cache.get(x)`) only use x to
# pick something.
CONTENT_METHODS = {name for kind in (str, bytes, pathlib.Path) for name in dir(kind)}


def _text(node: ast.AST) -> str | None:
    """The value of a string literal, or None for anything else."""
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _last_text(node: ast.AST) -> str | None:
    """The literal text an expression ends with, if it ends with one:
    "://" for `scheme + "://"`."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _last_text(node.right)
    if isinstance(node, ast.JoinedStr) and node.values:
        return _last_text(node.values[-1])
    return _text(node)


def _checked_name(node: ast.AST) -> str | None:
    """The variable a check is about: `x`, or `x` in `x or ""`."""
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
        first, *rest = node.values
        if all(isinstance(value, ast.Constant) for value in rest):
            node = first
    return node.id if isinstance(node, ast.Name) else None


def _mid_component(text: str | None) -> bool:
    """True if what follows this text continues the same path component:
    "report_" yes, "/srv/files/" no."""
    return bool(text) and text[-1] not in "/\\"


def _pick(index: int, keyword: str, positional: list, keywords: dict) -> Taint:
    """The taint of one particular argument of a call."""
    if keyword in keywords:
        return keywords[keyword]
    return positional[index] if index < len(positional) else CLEAN


def _leaves_host_open(prefix_end: str | None) -> bool:
    """True if what follows this text is still the host part of a URL."""
    return prefix_end is not None and prefix_end.endswith(("//", "@"))


def _strips_to_safe_characters(node: ast.Call) -> bool:
    """re.sub(r"[^a-zA-Z0-9_-]", "", x): keeps only characters from a class
    that has no "/" in it."""
    if len(node.args) < 3:
        return False
    pattern, replacement = _text(node.args[0]), _text(node.args[1])
    if pattern is None or replacement is None or "/" in replacement or ".." in replacement:
        return False
    match = re.fullmatch(STRIP_PATTERN, pattern)
    return match is not None and "/" not in match["kept"] and "\\\\" not in match["kept"]


def _root_name(node: ast.AST) -> str | None:
    """The variable at the start of a chain like `a.b[0].c()`."""
    while isinstance(node, (ast.Attribute, ast.Subscript, ast.Call)):
        node = node.func if isinstance(node, ast.Call) else node.value
    return node.id if isinstance(node, ast.Name) else None


def _union(states: list[State]) -> State:
    merged: State = {}
    for state in states:
        for name, taint in state.items():
            merged[name] = merged.get(name, CLEAN) | taint
    return merged


class Tracker:
    def __init__(
        self,
        module: Module,
        project,  # engine.project.Project: finds the function a call refers to
        findings: dict[tuple[str, str, int], Finding],
        summary: Summary,
        where: str,
        function: Function | None = None,  # None for module-level code
    ):
        self.module = module
        self.project = project
        self.findings = findings  # shared across the whole project
        self.summary = summary  # of the function being analyzed
        self.where = where  # its name, for messages
        self.function = function
        self.owner = function.owner if function else None  # its class, if it is a method
        self.guarded = function.guarded if function else False
        # Local variables known to hold an object: name -> class name.
        self.types: dict[str, str] = {}
        # `host = urlparse(url).hostname` -> {"host": "url"}: checking the
        # host against an allowlist vouches for the URL it came from.
        self.host_of: dict[str, str] = {}
        # `job = store.get_by_id(job_id)` -> {"job": ["job_id"]}: if the lookup
        # found something, the key it was given names an existing record.
        self.looked_up: dict[str, list[str]] = {}
        # Project functions this one calls (by id), so the project knows
        # what to analyze again when one of them changes.
        self.callees: set[int] = set()
        # Taint of each position of the returned tuple: None until the first
        # `return`, False once two returns disagree about the shape.
        self.returned_items: list[Taint] | None | bool = None

    # ---- statements -------------------------------------------------

    def run_block(self, statements: list[ast.stmt], state: State) -> None:
        for statement in statements:
            self.run_statement(statement, state)

    def run_statement(self, stmt: ast.stmt, state: State) -> None:
        match stmt:
            case ast.FunctionDef() | ast.AsyncFunctionDef() | ast.ClassDef():
                return  # nested definitions are analyzed on their own

            case ast.Assign():
                for target in stmt.targets:
                    self.assign(target, stmt.value, state)

            case ast.AnnAssign():
                if stmt.value is not None:
                    self.assign(stmt.target, stmt.value, state)

            case ast.AugAssign():  # x += y keeps whatever x already carried
                taint = self.eval(stmt.target, state) | self.eval(stmt.value, state)
                self.bind(stmt.target, unmarked(taint), state)

            case ast.Return():
                self.summary.returns |= self.eval(stmt.value, state)
                self.note_returned_items(stmt.value, state)

            case ast.If():
                self.eval(stmt.test, state)
                taken, skipped = dict(state), dict(state)
                # A check like `if name not in ALLOWED:` tells us something
                # about `name` on each side of the branch.
                self.apply_validation(stmt.test, True, taken)
                self.apply_validation(stmt.test, False, skipped)
                self.run_block(stmt.body, taken)
                self.run_block(stmt.orelse, skipped)
                if self.always_exits(stmt.body):
                    self.replace(state, skipped)  # only the other path continues
                elif self.always_exits(stmt.orelse):
                    self.replace(state, taken)
                else:
                    # Either branch may have run, so a variable is tainted
                    # afterwards if it is tainted at the end of either one.
                    self.replace(state, _union([taken, skipped]))

            case ast.For() | ast.AsyncFor():
                self.bind_loop(stmt.target, stmt.iter, state)
                self.run_loop(stmt.body, state)
                self.run_block(stmt.orelse, state)

            case ast.While():
                self.eval(stmt.test, state)
                self.run_loop(stmt.body, state)
                self.run_block(stmt.orelse, state)

            case ast.With() | ast.AsyncWith():
                for item in stmt.items:
                    taint = unmarked(self.eval(item.context_expr, state))
                    if item.optional_vars is not None:
                        self.bind(item.optional_vars, taint, state)
                        self.remember_type(item.optional_vars, item.context_expr)
                self.run_block(stmt.body, state)

            case ast.Try() | ast.TryStar():
                self.run_block(stmt.body, state)
                branches = [state]
                for handler in stmt.handlers:
                    branch = dict(state)
                    self.run_block(handler.body, branch)
                    branches.append(branch)
                self.replace(state, _union(branches))
                self.run_block(stmt.orelse, state)
                self.run_block(stmt.finalbody, state)

            case ast.Match():
                self.eval(stmt.subject, state)
                branches = [dict(state)]  # no case may match
                for case in stmt.cases:
                    branch = dict(state)
                    self.run_block(case.body, branch)
                    branches.append(branch)
                self.replace(state, _union(branches))

            case _:  # expression statement, raise, assert, ...
                for child in ast.iter_child_nodes(stmt):
                    if isinstance(child, ast.expr):
                        self.eval(child, state)

    def run_loop(self, body: list[ast.stmt], state: State) -> None:
        # A loop body may run zero or many times. Two passes are enough for
        # taint created late in the body to reach a use early in the body.
        for _ in range(2):
            iteration = dict(state)
            self.run_block(body, iteration)
            self.replace(state, _union([state, iteration]))

    @staticmethod
    def replace(state: State, new: State) -> None:
        state.clear()
        state.update(new)

    def note_returned_items(self, value: ast.expr | None, state: State) -> None:
        """Keep Summary.items up to date: per-position taint of a returned tuple."""
        if isinstance(value, ast.Tuple) and not any(isinstance(e, ast.Starred) for e in value.elts):
            items = [unmarked(self.eval(element, state)) for element in value.elts]
            if self.returned_items is None:
                self.returned_items = items
            elif self.returned_items and len(self.returned_items) == len(items):
                self.returned_items = [a | b for a, b in zip(self.returned_items, items)]
            else:
                self.returned_items = False
        elif not (value is None or (isinstance(value, ast.Constant) and value.value is None)):
            self.returned_items = False  # returns something that is not a tuple
        self.summary.items = tuple(self.returned_items) if self.returned_items else None

    def assign_from_tuple_return(self, target: ast.expr, value: ast.expr, state: State) -> bool:
        """`a, b = f()` where f always returns a 2-tuple: bind a and b separately."""
        if not (isinstance(target, (ast.Tuple, ast.List)) and isinstance(value, ast.Call)):
            return False
        if any(isinstance(e, ast.Starred) for e in target.elts):
            return False
        name = self.module.names.resolve(value.func)
        function = self.project_function(value, name)
        receiver = None
        if function is None:
            function, certain = self.find_method(value, name, self.receiver_type(value.func))
            if not certain:
                return False
            receiver = unmarked(self.eval(value.func, state))
        items = function.summary.items
        if items is None or len(items) != len(target.elts):
            return False
        positional = [self.eval(arg, state) for arg in value.args]
        keywords = {kw.arg: self.eval(kw.value, state) for kw in value.keywords}
        arguments = self.match_arguments(value, function, positional, keywords, receiver)
        for element, item in zip(target.elts, items):
            self.bind(element, self.substitute(item, arguments), state)
        return True

    def assign(self, target: ast.expr, value: ast.expr, state: State) -> None:
        sequence = (ast.Tuple, ast.List)
        if (
            isinstance(target, sequence)
            and isinstance(value, sequence)
            and len(target.elts) == len(value.elts)
            and not any(isinstance(e, ast.Starred) for e in [*target.elts, *value.elts])
        ):
            # a, b = c, d: match them up pairwise. Evaluate the whole right
            # side first so that a, b = b, a swaps correctly.
            taints = [self.eval(element, state) for element in value.elts]
            for element, taint in zip(target.elts, taints):
                self.bind(element, taint, state)
        else:
            taint = self.eval(value, state)  # always evaluated: this is what checks sinks
            if not self.assign_from_tuple_return(target, value, state):
                self.bind(target, taint, state)
            self.remember_type(target, value)
            self.remember_host(target, value)
            self.remember_lookup(target, value)

    def bind(self, target: ast.expr, taint: Taint, state: State) -> None:
        match target:
            case ast.Name():
                state[target.id] = taint  # overwrite: old taint is gone
                self.types.pop(target.id, None)
                self.host_of.pop(target.id, None)
                self.looked_up.pop(target.id, None)
            case ast.Tuple() | ast.List():
                for element in target.elts:
                    self.bind(element, unmarked(taint), state)
            case ast.Starred():
                self.bind(target.value, taint, state)
            case ast.Attribute() | ast.Subscript():
                # obj.x = t or d["k"] = t: the container now holds tainted
                # data, but its other contents are untouched, so only add.
                root = _root_name(target)
                if root is not None:
                    state[root] = state.get(root, CLEAN) | unmarked(taint)

    def bind_loop(self, target: ast.expr, iterable: ast.expr, state: State) -> None:
        """Bind the variable(s) of `for target in iterable`."""
        taint = unmarked(self.eval(iterable, state))
        if (
            isinstance(iterable, ast.Call)
            and self.module.names.resolve(iterable.func) == "enumerate"
            and isinstance(target, (ast.Tuple, ast.List))
            and len(target.elts) == 2
        ):
            # for i, item in enumerate(items): i is a counter, never tainted.
            self.bind(target.elts[0], CLEAN, state)
            self.bind(target.elts[1], taint, state)
        else:
            self.bind(target, taint, state)

    def remember_type(self, target: ast.expr, value: ast.expr) -> None:
        """After `s = requests.Session()` or `repo = Repo()`, note what s holds."""
        if isinstance(target, ast.Name):
            if isinstance(value, ast.Call):
                kind = self.project.class_name(self.module.names.resolve(value.func))
                if kind is not None:
                    self.types[target.id] = kind
            elif self.is_path(value):  # p = Path(base) / name
                self.types[target.id] = "pathlib.Path"

    def remember_lookup(self, target: ast.expr, value: ast.expr) -> None:
        """After `record = store.find(key)`: note which variables were the key."""
        if not (isinstance(target, ast.Name) and isinstance(value, ast.Call)):
            return
        if self.keeps_content(value, CLEAN):
            return  # builds its result from the arguments: not a lookup
        keys = [arg.id for arg in value.args if isinstance(arg, ast.Name)]
        keys += [kw.value.id for kw in value.keywords if isinstance(kw.value, ast.Name)]
        if keys:
            self.looked_up[target.id] = keys

    def remember_host(self, target: ast.expr, value: ast.expr) -> None:
        """After `parts = urlparse(url)` or `host = urlparse(url).hostname`."""
        if not isinstance(target, ast.Name):
            return
        if isinstance(value, ast.Attribute) and value.attr in URL_HOST_ATTRIBUTES:
            value = value.value
            if isinstance(value, ast.Name) and value.id in self.host_of:
                self.host_of[target.id] = self.host_of[value.id]
                return
        url = self.parsed_url(value)
        if url is not None:
            self.host_of[target.id] = url

    def parsed_url(self, node: ast.expr) -> str | None:
        """`url` if node is `urlparse(url)`."""
        if (
            isinstance(node, ast.Call)
            and self.module.names.resolve(node.func) in URL_PARSERS
            and node.args
            and isinstance(node.args[0], ast.Name)
        ):
            return node.args[0].id
        return None

    # ---- validation checks ------------------------------------------

    def always_exits(self, body: list[ast.stmt]) -> bool:
        """True if running this block always leaves the enclosing code."""
        if not body:
            return False
        last = body[-1]
        if isinstance(last, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
            return True
        if isinstance(last, ast.Expr) and isinstance(last.value, ast.Call):
            return self.module.names.resolve(last.value.func) in EXIT_CALLS
        if isinstance(last, ast.If):
            return self.always_exits(last.body) and self.always_exits(last.orelse)
        return False

    def apply_validation(self, test: ast.expr, outcome: bool, state: State) -> None:
        """Clear the variables that `test` vouches for when it comes out as `outcome`."""
        for name, rule, sure in self.vouched(test, outcome, state):
            if name not in state:
                continue
            taint = state[name]
            if not sure:
                # The check looks like validation but we cannot read it:
                # keep the taint, as weak, so it still shows up as low confidence.
                rules = [rule] if rule else [base(r) for r, _ in taint]
                for affected in set(rules):
                    taint = weaken_rule(taint, affected)
                state[name] = taint
            elif rule is None:
                state[name] = taint & {NORMALIZED}
            else:
                state[name] = without(taint, rule)

    def vouched(
        self, test: ast.expr, outcome: bool, state: State
    ) -> list[tuple[str, str | None, bool]]:
        """(variable, bug class, sure) triples for what `test` tells us when it
        equals `outcome`.

        A bug class of None means every bug class. `sure` is True for checks
        we understand (membership in a collection the attacker does not
        control, a regex match, startswith() on a resolved path): the taint
        is cleared. It is False for checks that only look like validation (a
        function with a safety-sounding name, a test for "/" or ".."): the
        taint is downgraded to weak instead.
        """
        match test:
            case ast.UnaryOp(op=ast.Not()):
                return self.vouched(test.operand, not outcome, state)

            case ast.BoolOp(op=ast.And()) if outcome:  # all parts held
                return [v for part in test.values for v in self.vouched(part, True, state)]

            case ast.BoolOp(op=ast.Or()) if not outcome:  # no part held
                return [v for part in test.values for v in self.vouched(part, False, state)]

            case ast.Compare(
                left=ast.Constant(value=str() as text),
                ops=[ast.In() | ast.NotIn() as op],
                comparators=[ast.Name(id=name)],
            ) if text in TRAVERSAL_TEXT:
                # `"/" in name` came out False (or `"/" not in name` True).
                if isinstance(op, ast.In) != outcome:
                    return [(name, PATH_TRAVERSAL, False)]

            case ast.Compare(ops=[ast.In() | ast.NotIn() as op], comparators=[collection]):
                is_member = isinstance(op, ast.In) == outcome
                if is_member and not self.eval(collection, state):
                    return self.member(test.left)

            case ast.Compare(ops=[op], comparators=[ast.Constant(value=None)]):
                # `re.match(p, x) is None` and `... is not None`
                if isinstance(op, (ast.Is, ast.Eq)):
                    return self.vouched(test.left, not outcome, state)
                if isinstance(op, (ast.IsNot, ast.NotEq)):
                    return self.vouched(test.left, outcome, state)

            case ast.Call() if outcome:
                return self.vouched_by_call(test, state)

            case ast.Name(id=name) if outcome and name in self.looked_up:
                # `job = store.get_by_id(job_id)` came back with something:
                # job_id names a record that exists. Not sure, so weak.
                return [(key, None, False) for key in self.looked_up[name]]
        return []

    def member(self, node: ast.expr) -> list[tuple[str, str | None, bool]]:
        """What `node in ALLOWED` vouches for."""
        if isinstance(node, ast.Name):
            vouched: list[tuple[str, str | None, bool]] = [(node.id, None, True)]
            if node.id in self.host_of:  # the host of a URL: the URL is fine for SSRF
                vouched.append((self.host_of[node.id], SSRF, True))
            return vouched
        if isinstance(node, ast.Attribute) and node.attr in URL_HOST_ATTRIBUTES:
            url = self.parsed_url(node.value)
            if url is None and isinstance(node.value, ast.Name):
                url = self.host_of.get(node.value.id)
            if url is not None:
                return [(url, SSRF, True)]
        return []

    def vouched_by_call(
        self, call: ast.Call, state: State
    ) -> list[tuple[str, str | None, bool]]:
        name = self.module.names.resolve(call.func)
        args = call.args
        # re.match(pattern, x)
        if name in REGEX_CHECKS and len(args) >= 2 and _checked_name(args[1]):
            return [(_checked_name(args[1]), None, True)]
        # is_trusted_url(x), path_is_child_of(x, base): the name claims the
        # value is safe, but we cannot check that it is. Not sure.
        if claims_safety(_last_name(call)):
            return [(arg.id, None, False) for arg in args if isinstance(arg, ast.Name)]
        if not isinstance(call.func, ast.Attribute) or len(args) != 1:
            return []
        receiver, method = call.func.value, call.func.attr
        # PATTERN.match(x), for a compiled pattern
        if method in ("match", "fullmatch") and _checked_name(args[0]):
            if not self.eval(receiver, state):
                return [(_checked_name(args[0]), None, True)]
        # resolved_path.startswith(base) and resolved_path.is_relative_to(base):
        # only mean something for a path that has been resolved first.
        if method in ("startswith", "is_relative_to") and not self.eval(args[0], state):
            if isinstance(receiver, ast.Name) and NORMALIZED in state.get(receiver.id, CLEAN):
                return [(receiver.id, PATH_TRAVERSAL, True)]
            if (
                isinstance(receiver, ast.Call)
                and self.module.names.resolve(receiver.func) in NORMALIZERS
                and receiver.args
                and isinstance(receiver.args[0], ast.Name)
            ):
                return [(receiver.args[0].id, PATH_TRAVERSAL, True)]
        return []

    # ---- expressions ------------------------------------------------

    def eval(self, node: ast.expr | None, state: State) -> Taint:
        """Taint of an expression. Visits every sub-expression, so every
        call inside it gets checked as a possible sink."""
        if node is None:
            return CLEAN
        method = getattr(self, f"eval_{type(node).__name__}", self.eval_children)
        taint = method(node, state)
        if not isinstance(node, (ast.Name, ast.Call, ast.NamedExpr, ast.IfExp)):
            # Anything built from a resolved path is no longer known to be one.
            taint = unmarked(taint)
        return taint

    def eval_IfExp(self, node: ast.IfExp, state: State) -> Taint:
        # `a.resolve() if cond else b.resolve()` is still a resolved path.
        self.eval(node.test, state)
        chosen, other = self.eval(node.body, state), self.eval(node.orelse, state)
        taint = chosen | other
        return taint if NORMALIZED in chosen and NORMALIZED in other else unmarked(taint)

    def eval_children(self, node: ast.AST, state: State) -> Taint:
        # Default rule: an expression is tainted if any part of it is.
        taint = CLEAN
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                taint |= self.eval(child, state)
        return taint

    def eval_Name(self, node: ast.Name, state: State) -> Taint:
        return state.get(node.id, CLEAN)

    def eval_Constant(self, node: ast.Constant, state: State) -> Taint:
        return CLEAN

    def eval_Lambda(self, node: ast.Lambda, state: State) -> Taint:
        return CLEAN

    def eval_Compare(self, node: ast.Compare, state: State) -> Taint:
        self.eval_children(node, state)
        return CLEAN  # the result is only True or False

    def eval_NamedExpr(self, node: ast.NamedExpr, state: State) -> Taint:
        taint = self.eval(node.value, state)
        self.bind(node.target, taint, state)
        return taint

    def eval_Yield(self, node: ast.Yield, state: State) -> Taint:
        self.summary.returns |= self.eval(node.value, state)  # a yield hands data back too
        return CLEAN

    eval_YieldFrom = eval_Yield

    def eval_Attribute(self, node: ast.Attribute, state: State) -> Taint:
        name = self.module.names.resolve(node)
        if name is not None:
            prefix, _, attribute = name.rpartition(".")
            if prefix == "flask.request" and attribute in REQUEST_SOURCES:
                return from_source(FROM_REQUEST)
        taint = self.eval(node.value, state)  # tainted.attr is tainted
        if node.attr in PATH_LAST_COMPONENT and self.is_path(node.value):
            return without(taint, PATH_TRAVERSAL)  # Path(x).name has no directory part
        if node.attr in KEY_ATTRIBUTES:
            return weaken(taint)  # record.id is a key, not content
        return taint

    def is_path(self, node: ast.expr) -> bool:
        """True if the expression is known to be a pathlib path object."""
        if isinstance(node, ast.Call):
            return self.module.names.resolve(node.func) in PATH_CLASSES
        if isinstance(node, ast.Name):
            return self.types.get(node.id) in PATH_CLASSES
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            return self.is_path(node.left)  # Path(base) / name
        return False

    def text(self, node: ast.AST | None, state: State) -> str | None:
        """The text of a string literal, or of a module-level string constant."""
        literal = _text(node) if node is not None else None
        if literal is not None:
            return literal
        if isinstance(node, ast.FormattedValue) and node.conversion == -1 and node.format_spec is None:
            node = node.value  # f"{BASE_URL}..." names a constant
        if isinstance(node, ast.Name) and node.id not in state:
            if node.id in self.module.constants:
                return self.module.constants[node.id]
            return self.project.constant(self.module.names.resolve(node))
        if isinstance(node, ast.Attribute):  # config.BASE_URL
            return self.project.constant(self.module.names.resolve(node))
        return None

    def eval_Subscript(self, node: ast.Subscript, state: State) -> Taint:
        # table[key]: a tainted key only picks which entry comes back.
        return self.eval(node.value, state) | weaken(self.eval(node.slice, state))

    def eval_BinOp(self, node: ast.BinOp, state: State) -> Taint:
        left, right = self.eval(node.left, state), self.eval(node.right, state)
        if not isinstance(node.op, (ast.Add, ast.Mod)):
            return left | right
        prefix = self.text(node.left, state)
        if isinstance(node.op, ast.Add) and _mid_component(_last_text(node.left) or prefix):
            # "report_" + x: x starts in the middle of a file name. "../" in
            # it then needs a directory called "report_.." to exist, so this
            # only escapes on Windows, which resolves ".." without looking.
            right = weaken_rule(right, PATH_TRAVERSAL)
        if isinstance(node.op, ast.Mod):  # "https://api.example.com/%s" % x
            if prefix is not None and PINNED_HOST.match(prefix.split("%")[0]):
                return without(left | right, SSRF)
            return left | right
        if prefix is not None and PINNED_HOST.match(prefix):  # "https://api.example.com/" + x
            return without(left | right, SSRF)
        if not left and prefix is None and not _leaves_host_open(_last_text(node.left)):
            # BASE_URL + x: the start of the URL is not the attacker's and is
            # not a literal we can read. They most likely control only the path.
            return weaken_rule(right, SSRF)
        return left | right

    def eval_JoinedStr(self, node: ast.JoinedStr, state: State) -> Taint:
        # Walk the pieces of an f-string left to right, applying the same
        # rules as for "+": what comes before a tainted piece decides how
        # much of the URL the attacker controls.
        taint = CLEAN
        literal_so_far: str | None = ""  # None once a non-literal piece was seen
        previous: ast.expr | None = None
        for piece in node.values:
            piece_taint = self.eval(piece, state)
            if piece_taint and not taint:
                if literal_so_far and PINNED_HOST.match(literal_so_far):
                    piece_taint = without(piece_taint, SSRF)
                elif literal_so_far is None and not _leaves_host_open(self.text(previous, state)):
                    piece_taint = weaken_rule(piece_taint, SSRF)
            elif piece_taint and taint and PINNED_HOST.match(literal_so_far or ""):
                piece_taint = without(piece_taint, SSRF)
            if piece_taint and previous is not None and _mid_component(self.text(previous, state)):
                piece_taint = weaken_rule(piece_taint, PATH_TRAVERSAL)  # f"report_{x}.json"
            taint |= piece_taint
            text = self.text(piece, state)
            if text is not None and literal_so_far is not None:
                literal_so_far += text
            elif not piece_taint:
                literal_so_far = None
            previous = piece
        return taint

    def eval_Call(self, node: ast.Call, state: State) -> Taint:
        name = self.module.names.resolve(node.func)
        # Evaluating the callee covers both sources (request.get_json())
        # and methods on tainted values (url.strip()).
        callee_taint = unmarked(self.eval(node.func, state))
        positional = [self.eval(arg, state) for arg in node.args]
        keywords = {kw.arg: self.eval(kw.value, state) for kw in node.keywords}
        receiver_type = self.receiver_type(node.func)
        typed_name = None

        self.check_sink(node, name, positional, keywords)
        if receiver_type is not None:  # session.get(url), where session is a requests.Session
            typed_name = f"{receiver_type}.{node.func.attr}"
            self.check_sink(node, typed_name, positional, keywords)
        self.check_receiver_sink(node, callee_taint, positional, keywords)

        taint = self.call_result(node, name, typed_name, receiver_type, callee_taint, positional, keywords, state)
        if claims_safety(_last_name(node)) and name not in SANITIZERS:
            # safe_path(x), validate_outbound_url(x): the name claims the result
            # is safe. We cannot check that, so the taint stays, as weak.
            taint = weaken(taint) | (taint & {NORMALIZED})
        return taint

    def project_function(self, node: ast.Call, name: str | None) -> Function | None:
        """The project function a call names: a top-level one, or one nested
        in the same enclosing function (a helper inside an app factory)."""
        function = self.project.lookup(name) if name else None
        if function is None and isinstance(node.func, ast.Name) and self.function is not None:
            function = self.project.scoped_function(self.function, node.func.id)
        return function

    def call_result(
        self, node, name, typed_name, receiver_type, callee_taint, positional, keywords, state
    ) -> Taint:
        """The taint of what a call returns."""
        function = self.project_function(node, name)
        if function is not None:
            # We have the callee's code, so use what it actually does.
            return self.apply_summary(node, function, positional, keywords)

        arguments = CLEAN
        for argument_taint in [*positional, *keywords.values()]:
            arguments |= unmarked(argument_taint)
        if name in CLEANERS:
            return CLEAN
        if name in SANITIZERS:
            return without(callee_taint | arguments, SANITIZERS[name])
        if name == "re.sub" and _strips_to_safe_characters(node):
            return without(unmarked(positional[2]), PATH_TRAVERSAL)
        if name in TEMPFILE_CALLS:
            return weaken_rule(callee_taint | arguments, PATH_TRAVERSAL)
        if name in CARRIERS:  # Request(url, data=...): only the URL matters
            return unmarked(_pick(*CARRIERS[name], positional, keywords))
        for http_call in (name, typed_name):
            if http_call in SINKS and SINKS[http_call][0] == SSRF:
                # The response comes from wherever the URL points. A tainted
                # body or header sent to a fixed host does not make the
                # reply attacker-controlled.
                _, index, keyword = SINKS[http_call]
                return unmarked(_pick(index, keyword, positional, keywords)) | weaken(arguments)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            template = self.text(node.func.value, state)
            if template is not None and PINNED_HOST.match(template.split("{")[0]):
                # "https://api.example.com/{}".format(x): the host is fixed
                return without(callee_taint | arguments, SSRF)

        # Unknown callee. If it builds its result out of the arguments, the
        # result is as tainted as they are; if it only looks something up
        # with them, the result is weakly tainted.
        if not self.keeps_content(node, callee_taint):
            arguments = weaken(arguments)
        taint = callee_taint | arguments
        resolves_path = name in NORMALIZERS or getattr(node.func, "attr", None) == "resolve"
        if taint and resolves_path:
            taint |= {NORMALIZED}

        method, certain = self.find_method(node, name, receiver_type)
        if method is not None:
            result = self.apply_summary(node, method, positional, keywords, callee_taint)
            # A guessed method may be the wrong one, so it can only add taint.
            taint = result if certain else taint | result
        return taint

    def keeps_content(self, node: ast.Call, callee_taint: Taint) -> bool:
        """Does this unknown call build its result from its arguments?

        Yes for plain functions, library calls, string and path methods,
        and methods on a tainted value. No for a method on one of the
        project's own objects or a local variable: `db.get_book(book_id)`
        hands back a record the attacker picked but did not write.
        """
        func = node.func
        if not isinstance(func, ast.Attribute) or callee_taint:
            return True
        if func.attr in CONTENT_METHODS or isinstance(func.value, (ast.Constant, ast.JoinedStr)):
            return True
        root = _root_name(func.value)
        names = self.module.names
        if root is None or root in names.imported_modules:
            return True
        if root in names.aliases:  # from x import y: a library, unless x is ours
            return not self.project.is_internal(names.aliases[root])
        return False

    def receiver_type(self, func: ast.expr) -> str | None:
        """The class of `obj` in `obj.method(...)`, when we can tell."""
        if not isinstance(func, ast.Attribute):
            return None
        receiver = func.value
        names = self.module.names
        if isinstance(receiver, ast.Call):  # Repo().load(x)
            return self.project.class_name(names.resolve(receiver.func))
        if not isinstance(receiver, ast.Name):
            return None
        if receiver.id in self.types:
            return self.types[receiver.id]
        for candidate in (names.resolve(receiver), f"{self.module.name}.{receiver.id}"):
            # a module-level object (db = Database()), or the class itself
            kind = self.project.instance_type(candidate) or self.project.class_name(candidate)
            if kind is not None:
                return kind
        return None

    def find_method(
        self, node: ast.Call, name: str | None, receiver_type: str | None
    ) -> tuple[Function | None, bool]:
        """The project method `obj.method(...)` calls, and whether that is certain."""
        if not isinstance(node.func, ast.Attribute) or name in SINKS:
            return None, False
        receiver, method = node.func.value, node.func.attr
        if isinstance(receiver, ast.Name) and receiver.id in ("self", "cls") and self.owner:
            receiver_type = self.owner
        if receiver_type is not None:
            known = self.project.method_of(receiver_type, method)
            if known is not None:
                return known, True
        if _root_name(receiver) in self.module.names.imported_modules:
            return None, False  # os.path.join(...): a module function, not a method
        return self.project.unique_method(method), False

    def eval_comprehension(self, node, state: State) -> Taint:
        inner = dict(state)  # loop variables do not leak out
        for generator in node.generators:
            self.bind_loop(generator.target, generator.iter, inner)
            for condition in generator.ifs:
                self.eval(condition, inner)
        if isinstance(node, ast.DictComp):
            return self.eval(node.key, inner) | self.eval(node.value, inner)
        return self.eval(node.elt, inner)

    eval_ListComp = eval_SetComp = eval_GeneratorExp = eval_DictComp = eval_comprehension

    # ---- calls into project functions -------------------------------

    def apply_summary(
        self, node, function: Function, positional, keywords, receiver: Taint | None = None
    ) -> Taint:
        arguments = self.match_arguments(node, function, positional, keywords, receiver)
        summary = function.summary
        self.callees.add(id(function))
        if function.guarded:
            # We called a helper that runs a validator-looking check
            # (`fp = _file_for(link, sub)`). Ranking signal only.
            self.guarded = True

        # Sinks inside the callee that one of our arguments reaches.
        for param, hits in summary.param_sinks.items():
            for rule, origin in arguments.get(param, CLEAN):
                for hit in hits:
                    if hit.rule == base(rule):
                        passed_on = replace(
                            hit,
                            weak=hit.weak or is_weak(rule),
                            depth=min(hit.depth + 1, 5),  # capped so recursion settles
                            guarded=hit.guarded or self.guarded,
                        )
                        self.report(passed_on, origin, node.lineno)

        return self.substitute(summary.returns, arguments)

    @staticmethod
    def substitute(returned: Taint, arguments: dict[str, Taint]) -> Taint:
        """A callee's return taint, with each parameter label swapped for
        whatever was actually passed for that parameter. Weak on either
        side stays weak."""
        result: set = set()
        for rule, origin in returned:
            if is_real(origin):
                result.add((rule, origin))
                continue
            for argument_rule, argument_origin in arguments.get(origin, CLEAN):
                if base(argument_rule) == base(rule):
                    weak = is_weak(rule) or is_weak(argument_rule)
                    result.add((("~" if weak else "") + base(rule), argument_origin))
        return frozenset(result)

    @staticmethod
    def match_arguments(
        node, function: Function, positional, keywords, receiver: Taint | None = None
    ) -> dict[str, Taint]:
        """Which taint lands in which parameter of the callee.

        `receiver` is the taint of `obj` in `obj.method(...)`; it fills `self`.
        """
        everything = receiver or CLEAN
        for taint in [*positional, *keywords.values()]:
            everything |= taint
        if any(isinstance(arg, ast.Starred) for arg in node.args) or None in keywords:
            # f(*args) or f(**kwargs): cannot tell what goes where.
            return {param: everything for param in function.params}

        arguments: dict[str, Taint] = {}

        def add(param: str | None, taint: Taint) -> None:
            if param is not None:
                arguments[param] = arguments.get(param, CLEAN) | taint

        names = function.positional
        if receiver is not None and function.binds_receiver and names:
            # A tainted object is not tainted in every field: `self.x` inside
            # the method may or may not be the part the attacker supplied.
            add(names[0], weaken(receiver))
            names = names[1:]
        for index, taint in enumerate(positional):
            add(names[index] if index < len(names) else function.vararg, taint)
        for keyword, taint in keywords.items():
            add(keyword if keyword in function.params else function.kwarg, taint)
        return arguments

    # ---- sinks ------------------------------------------------------

    def check_sink(self, node, name, positional, keywords) -> None:
        if name not in SINKS:
            return
        rule, index, keyword = SINKS[name]
        if keyword in keywords:
            taint = keywords[keyword]
        elif index < len(positional):
            taint = positional[index]
        else:
            return
        hit = SinkHit(rule, self.module.file, node.lineno, name, keyword, guarded=self.guarded)
        self.report_reaching(hit, taint)

    def check_receiver_sink(self, node: ast.Call, receiver_taint: Taint, positional, keywords) -> None:
        """Sinks that depend on what the method is called on.

        Path(user_input).read_text(): the tainted value is the object itself.
        request.files["f"].save(path): an uploaded file written to a tainted path.
        """
        method = getattr(node.func, "attr", None)
        if method in UPLOAD_SINKS and any(not is_weak(rule) for rule, _ in receiver_taint):
            rule, index, keyword = UPLOAD_SINKS[method]
            hit = SinkHit(rule, self.module.file, node.lineno, method, keyword, guarded=self.guarded)
            self.report_reaching(hit, _pick(index, keyword, positional, keywords))
        if method in RECEIVER_SINKS:
            hit = SinkHit(
                RECEIVER_SINKS[method], self.module.file, node.lineno, method, "self",
                guarded=self.guarded,
            )  # fmt: skip
            self.report_reaching(hit, receiver_taint)

    def report_reaching(self, hit: SinkHit, taint: Taint) -> None:
        for rule, origin in taint:
            if base(rule) == hit.rule:
                self.report(replace(hit, weak=is_weak(rule)), origin)

    def auth(self) -> str:
        """ "admin", "login", "hook" or "none" for the function being analyzed.

        "hook": no login decorator, but the app has a before_request hook,
        which is where many apps check the session for every route.
        """
        found = self.function.auth if self.function else "none"
        if found == "none" and self.project.has_request_hook:
            return "hook"
        return found

    def report(self, hit: SinkHit, origin: str | None, call_line: int | None = None) -> None:
        """Record that data with this origin reaches a sink.

        `call_line` is set when the sink is inside a function we called: it
        is the line of that call in the function being analyzed.
        """
        if not is_real(origin):
            # Only dangerous if our caller passes tainted data for this
            # parameter: note it in the summary and let the caller decide.
            self.summary.param_sinks.setdefault(origin, set()).add(hit)
            return
        entry = Entry(
            function=self.where,
            file=self.module.file,
            line=call_line or hit.line,
            source=origin[1:] if origin else FROM_REQUEST,
            depth=hit.depth,
            route=bool(self.function and is_route(self.function.node)),
            auth=self.auth(),
            guarded=hit.guarded or self.guarded,
        )
        confidence = LOW if hit.weak else HIGH
        key = (hit.rule, hit.file, hit.line)
        existing = self.findings.get(key)
        if existing is None or (existing.confidence == LOW and confidence == HIGH):
            message = f"untrusted input reaches {hit.sink}() argument '{hit.argument}'"
            self.findings[key] = Finding(
                hit.rule, hit.file, hit.line, message, confidence, (entry,)
            )
        elif existing.confidence == confidence and len(existing.entries) < 20:
            # The same sink reached another way: keep every entry point,
            # one per function and source.
            seen = {(e.function, e.source) for e in existing.entries}
            if (entry.function, entry.source) not in seen:
                self.findings[key] = replace(existing, entries=(*existing.entries, entry))
