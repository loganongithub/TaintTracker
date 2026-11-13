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
import re

from taintscan.engine.model import Function, Module, SinkHit, Summary
from taintscan.engine.taint import CLEAN, FROM_SOURCE, Taint, without
from taintscan.finding import SSRF, Finding
from taintscan.rules import CLEANERS, REQUEST_SOURCES, SANITIZERS, SINKS

State = dict[str, Taint]

# A constant prefix like "https://api.example.com/" fixes the host.
# "https://api.example.com" (no slash) does not: "@evil.com" can follow it.
PINNED_HOST = re.compile(r"^https?://[^/@?#]+/")


def _pins_host(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and bool(PINNED_HOST.match(node.value))
    )


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
                self.bind(stmt.target, taint, state)

            case ast.Return():
                self.summary.returns |= self.eval(stmt.value, state)

            case ast.If():
                # Either branch may run, so afterwards a variable is tainted
                # if it is tainted at the end of either one.
                self.eval(stmt.test, state)
                taken, skipped = dict(state), dict(state)
                self.run_block(stmt.body, taken)
                self.run_block(stmt.orelse, skipped)
                self.replace(state, _union([taken, skipped]))

            case ast.For() | ast.AsyncFor():
                self.bind(stmt.target, self.eval(stmt.iter, state), state)
                self.run_loop(stmt.body, state)
                self.run_block(stmt.orelse, state)

            case ast.While():
                self.eval(stmt.test, state)
                self.run_loop(stmt.body, state)
                self.run_block(stmt.orelse, state)

            case ast.With() | ast.AsyncWith():
                for item in stmt.items:
                    taint = self.eval(item.context_expr, state)
                    if item.optional_vars is not None:
                        self.bind(item.optional_vars, taint, state)
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

    def bind(self, target: ast.expr, taint: Taint, state: State) -> None:
        match target:
            case ast.Name():
                state[target.id] = taint  # overwrite: old taint is gone
            case ast.Tuple() | ast.List():
                for element in target.elts:
                    self.bind(element, taint, state)
            case ast.Starred():
                self.bind(target.value, taint, state)
            case ast.Attribute() | ast.Subscript():
                # obj.x = t or d["k"] = t: the container now holds tainted
                # data, but its other contents are untouched, so only add.
                root = target
                while isinstance(root, (ast.Attribute, ast.Subscript)):
                    root = root.value
                if isinstance(root, ast.Name):
                    state[root.id] = state.get(root.id, CLEAN) | taint

    # ---- expressions ------------------------------------------------

    def eval(self, node: ast.expr | None, state: State) -> Taint:
        """Taint of an expression. Visits every sub-expression, so every
        call inside it gets checked as a possible sink."""
        if node is None:
            return CLEAN
        method = getattr(self, f"eval_{type(node).__name__}", self.eval_children)
        return method(node, state)

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
        callee_taint = self.eval(node.func, state)
        positional = [self.eval(arg, state) for arg in node.args]
        keywords = {kw.arg: self.eval(kw.value, state) for kw in node.keywords}

        self.check_sink(node, name, positional, keywords)

        function = self.project.lookup(name) if name else None
        if function is not None:
            # We have the callee's code, so use what it actually does.
            return self.apply_summary(node, function, positional, keywords)

        # Unknown callee: assume the result is tainted if anything going in is.
        taint = callee_taint
        for argument_taint in [*positional, *keywords.values()]:
            taint |= argument_taint
        if name in CLEANERS:
            return CLEAN
        if name in SANITIZERS:
            return without(taint, SANITIZERS[name])

        method, certain = self.find_method(node, name)
        if method is not None:
            result = self.apply_summary(node, method, positional, keywords, callee_taint)
            # A guessed method may be the wrong one, so it can only add taint.
            taint = result if certain else taint | result
        return taint

    def find_method(self, node: ast.Call, name: str | None) -> tuple[Function | None, bool]:
        """The project method `obj.method(...)` calls, and whether that is certain."""
        if not isinstance(node.func, ast.Attribute) or name in SINKS:
            return None, False
        receiver, method = node.func.value, node.func.attr
        if isinstance(receiver, ast.Name) and receiver.id in ("self", "cls") and self.owner:
            own = self.project.method_of(self.owner, method)
            if own is not None:
                return own, True
        root = receiver
        while isinstance(root, (ast.Attribute, ast.Subscript, ast.Call)):
            root = root.func if isinstance(root, ast.Call) else root.value
        if isinstance(root, ast.Name) and root.id in self.module.names.imported_modules:
            return None, False  # os.path.join(...): a module function, not a method
        return self.project.unique_method(method), False

    def eval_comprehension(self, node, state: State) -> Taint:
        inner = dict(state)  # loop variables do not leak out
        for generator in node.generators:
            self.bind(generator.target, self.eval(generator.iter, inner), inner)
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
                    if hit.rule == rule:
                        self.report(hit, origin, via)

        # The return value: swap each parameter label for whatever we
        # actually passed for that parameter.
        result: set = set()
        for rule, origin in summary.returns:
            if origin is None:
                result.add((rule, None))
            else:
                result |= {label for label in arguments.get(origin, CLEAN) if label[0] == rule}
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
            add(names[0], receiver)
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
        hit = SinkHit(rule, self.module.file, node.lineno, name, keyword)
        for label_rule, origin in taint:
            if label_rule == rule:
                self.report(hit, origin)

    def report(self, hit: SinkHit, origin: str | None, via: str = "") -> None:
        if origin is not None:
            # Only dangerous if our caller passes tainted data for this
            # parameter: note it in the summary and let the caller decide.
            self.summary.param_sinks.setdefault(origin, set()).add(hit)
            return
        message = f"untrusted input reaches {hit.sink}() argument '{hit.argument}'"
        if via:
            message += f", {via}"
        self.findings.setdefault(
            (hit.rule, hit.file, hit.line),
            Finding(rule=hit.rule, file=hit.file, line=hit.line, message=message),
        )
