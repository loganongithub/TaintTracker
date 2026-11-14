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

from taintscan.engine.model import Function, Module, SinkHit, Summary
from taintscan.engine.taint import (
    CLEAN,
    FROM_SOURCE,
    NORMALIZED,
    Taint,
    base,
    is_weak,
    unmarked,
    weaken,
    without,
)
from taintscan.finding import HIGH, LOW, PATH_TRAVERSAL, SSRF, Finding
from taintscan.rules import (
    CLEANERS,
    EXIT_CALLS,
    NORMALIZERS,
    RECEIVER_SINKS,
    REGEX_CHECKS,
    REQUEST_SOURCES,
    SANITIZERS,
    SINKS,
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


def _pins_host(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and bool(PINNED_HOST.match(node.value))
    )


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
        owner: str | None = None,
    ):
        self.module = module
        self.project = project
        self.findings = findings  # shared across the whole project
        self.summary = summary  # of the function being analyzed
        self.where = where  # its name, for messages
        self.owner = owner  # its class, if it is a method
        # Local variables known to hold an object: name -> class name.
        self.types: dict[str, str] = {}
        # `host = urlparse(url).hostname` -> {"host": "url"}: checking the
        # host against an allowlist vouches for the URL it came from.
        self.host_of: dict[str, str] = {}

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
                self.bind(stmt.target, unmarked(self.eval(stmt.iter, state)), state)
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
            self.bind(target, self.eval(value, state), state)
            self.remember_type(target, value)
            self.remember_host(target, value)

    def bind(self, target: ast.expr, taint: Taint, state: State) -> None:
        match target:
            case ast.Name():
                state[target.id] = taint  # overwrite: old taint is gone
                self.types.pop(target.id, None)
                self.host_of.pop(target.id, None)
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

    def remember_type(self, target: ast.expr, value: ast.expr) -> None:
        """After `s = requests.Session()` or `repo = Repo()`, note what s holds."""
        if isinstance(target, ast.Name) and isinstance(value, ast.Call):
            kind = self.project.class_name(self.module.names.resolve(value.func))
            if kind is not None:
                self.types[target.id] = kind

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
        for name, rule in self.vouched(test, outcome, state):
            if name not in state:
                continue
            if rule is None:
                state[name] = state[name] & {NORMALIZED}
            else:
                state[name] = without(state[name], rule)

    def vouched(self, test: ast.expr, outcome: bool, state: State) -> list[tuple[str, str | None]]:
        """(variable, bug class) pairs known safe when `test` equals `outcome`.

        A bug class of None means safe for everything. Only three kinds of
        check are understood: membership in a collection the attacker does
        not control, a regex match, and startswith() on a resolved path.
        """
        match test:
            case ast.UnaryOp(op=ast.Not()):
                return self.vouched(test.operand, not outcome, state)

            case ast.BoolOp(op=ast.And()) if outcome:  # all parts held
                return [v for part in test.values for v in self.vouched(part, True, state)]

            case ast.BoolOp(op=ast.Or()) if not outcome:  # no part held
                return [v for part in test.values for v in self.vouched(part, False, state)]

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
        return []

    def member(self, node: ast.expr) -> list[tuple[str, str | None]]:
        """What `node in ALLOWED` vouches for."""
        if isinstance(node, ast.Name):
            vouched: list[tuple[str, str | None]] = [(node.id, None)]
            if node.id in self.host_of:  # the host of a URL: the URL is fine for SSRF
                vouched.append((self.host_of[node.id], SSRF))
            return vouched
        if isinstance(node, ast.Attribute) and node.attr in URL_HOST_ATTRIBUTES:
            url = self.parsed_url(node.value)
            if url is None and isinstance(node.value, ast.Name):
                url = self.host_of.get(node.value.id)
            if url is not None:
                return [(url, SSRF)]
        return []

    def vouched_by_call(self, call: ast.Call, state: State) -> list[tuple[str, str | None]]:
        name = self.module.names.resolve(call.func)
        args = call.args
        # re.match(pattern, x)
        if name in REGEX_CHECKS and len(args) >= 2 and isinstance(args[1], ast.Name):
            return [(args[1].id, None)]
        if not isinstance(call.func, ast.Attribute) or len(args) != 1:
            return []
        receiver, method = call.func.value, call.func.attr
        # PATTERN.match(x), for a compiled pattern
        if method in ("match", "fullmatch") and isinstance(args[0], ast.Name):
            if not self.eval(receiver, state):
                return [(args[0].id, None)]
        # resolved_path.startswith(base): only means something for a path
        # that has been through realpath/abspath/normpath.
        if method == "startswith" and not self.eval(args[0], state):
            if isinstance(receiver, ast.Name) and NORMALIZED in state.get(receiver.id, CLEAN):
                return [(receiver.id, PATH_TRAVERSAL)]
            if (
                isinstance(receiver, ast.Call)
                and self.module.names.resolve(receiver.func) in NORMALIZERS
                and receiver.args
                and isinstance(receiver.args[0], ast.Name)
            ):
                return [(receiver.args[0].id, PATH_TRAVERSAL)]
        return []

    # ---- expressions ------------------------------------------------

    def eval(self, node: ast.expr | None, state: State) -> Taint:
        """Taint of an expression. Visits every sub-expression, so every
        call inside it gets checked as a possible sink."""
        if node is None:
            return CLEAN
        method = getattr(self, f"eval_{type(node).__name__}", self.eval_children)
        taint = method(node, state)
        if not isinstance(node, (ast.Name, ast.Call, ast.NamedExpr)):
            # Anything built from a resolved path is no longer known to be one.
            taint = unmarked(taint)
        return taint

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
                return FROM_SOURCE
        return self.eval(node.value, state)  # tainted.attr is tainted

    def eval_Subscript(self, node: ast.Subscript, state: State) -> Taint:
        # table[key]: a tainted key only picks which entry comes back.
        return self.eval(node.value, state) | weaken(self.eval(node.slice, state))

    def eval_BinOp(self, node: ast.BinOp, state: State) -> Taint:
        taint = self.eval(node.left, state) | self.eval(node.right, state)
        if isinstance(node.op, ast.Add) and _pins_host(node.left):
            taint = without(taint, SSRF)
        return taint

    def eval_JoinedStr(self, node: ast.JoinedStr, state: State) -> Taint:
        taint = self.eval_children(node, state)
        if node.values and _pins_host(node.values[0]):
            taint = without(taint, SSRF)
        return taint

    def eval_Call(self, node: ast.Call, state: State) -> Taint:
        name = self.module.names.resolve(node.func)
        # Evaluating the callee covers both sources (request.get_json())
        # and methods on tainted values (url.strip()).
        callee_taint = unmarked(self.eval(node.func, state))
        positional = [self.eval(arg, state) for arg in node.args]
        keywords = {kw.arg: self.eval(kw.value, state) for kw in node.keywords}
        receiver_type = self.receiver_type(node.func)

        self.check_sink(node, name, positional, keywords)
        if receiver_type is not None:  # session.get(url), where session is a requests.Session
            typed_name = f"{receiver_type}.{node.func.attr}"
            self.check_sink(node, typed_name, positional, keywords)
        self.check_receiver_sink(node, callee_taint)

        function = self.project.lookup(name) if name else None
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
            self.bind(generator.target, unmarked(self.eval(generator.iter, inner)), inner)
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
        via = f"passed in by {self.where} ({self.module.file}:{node.lineno})"

        # Sinks inside the callee that one of our arguments reaches.
        for param, hits in summary.param_sinks.items():
            for rule, origin in arguments.get(param, CLEAN):
                for hit in hits:
                    if hit.rule == base(rule):
                        weak = hit.weak or is_weak(rule)
                        self.report(replace(hit, weak=weak), origin, via)

        # The return value: swap each parameter label for whatever we
        # actually passed for that parameter. Weak on either side stays weak.
        result: set = set()
        for rule, origin in summary.returns:
            if origin is None:
                result.add((rule, None))
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
        self.report_reaching(SinkHit(rule, self.module.file, node.lineno, name, keyword), taint)

    def check_receiver_sink(self, node: ast.Call, receiver_taint: Taint) -> None:
        """Path(user_input).read_text(): the tainted value is the object itself."""
        method = getattr(node.func, "attr", None)
        if method in RECEIVER_SINKS:
            hit = SinkHit(RECEIVER_SINKS[method], self.module.file, node.lineno, method, "self")
            self.report_reaching(hit, receiver_taint)

    def report_reaching(self, hit: SinkHit, taint: Taint) -> None:
        for rule, origin in taint:
            if base(rule) == hit.rule:
                self.report(replace(hit, weak=is_weak(rule)), origin)

    def report(self, hit: SinkHit, origin: str | None, via: str = "") -> None:
        if origin is not None:
            # Only dangerous if our caller passes tainted data for this
            # parameter: note it in the summary and let the caller decide.
            self.summary.param_sinks.setdefault(origin, set()).add(hit)
            return
        confidence = LOW if hit.weak else HIGH
        key = (hit.rule, hit.file, hit.line)
        existing = self.findings.get(key)
        if existing is not None and (existing.confidence == HIGH or confidence == LOW):
            return  # keep the first finding, unless this one is more certain
        message = f"untrusted input reaches {hit.sink}() argument '{hit.argument}'"
        if via:
            message += f", {via}"
        self.findings[key] = Finding(hit.rule, hit.file, hit.line, message, confidence)
