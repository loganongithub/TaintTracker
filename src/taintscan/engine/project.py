"""Loads every Python file under a directory and analyzes them together.

Cross-function tracking works with summaries. Every function gets a
Summary (model.py) describing what it does with its parameters. Because
functions call each other, the summaries are computed in rounds: each
round re-analyzes every function using the summaries from the round
before, and the loop stops when nothing changes.
"""

import ast
import io
import warnings
from pathlib import Path

from taintscan.engine.model import TEST_CODE, Class, Function, Module, Summary
from taintscan.engine.names import ImportMap
from taintscan.engine.routes import tainted_params
from taintscan.engine.taint import from_param, from_source
from taintscan.engine.tracker import Tracker
from taintscan.finding import Finding
from taintscan.rules import PATH_CLASSES, SINK_CLASSES

SKIP_DIRS = {".venv", "venv", "env", ".git", "__pycache__", "node_modules", "site-packages"}
MAX_ROUNDS = 10  # summaries only ever grow, so this is a safety cap

# Method names of built-in types. `d.get(k)` or `f.read()` is far more likely
# to be a dict or a file than a project class that happens to share the name.
BUILTIN_METHODS = {
    name
    for kind in (str, bytes, bytearray, dict, list, set, frozenset, tuple, int, float,
                 io.TextIOWrapper, io.BufferedReader, io.BytesIO)
    for name in dir(kind)
}


def python_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    return [p for p in sorted(root.rglob("*.py")) if not SKIP_DIRS.intersection(p.parts)]


def _decorator_name(node: ast.AST) -> str:
    """`before_request` from `@app.before_request` or `@bp.before_request()`."""
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Attribute):
        return node.attr
    return node.id if isinstance(node, ast.Name) else ""


def _suffix_index(names, min_parts: int) -> dict[str, str | None]:
    """Maps every dotted suffix of each name to the name, or None if two share it.

    Lets `pkg.mod.f` find "src.pkg.mod.f" when the scan root sits above
    the real import root.
    """
    index: dict[str, str | None] = {}
    for name in names:
        parts = name.split(".")
        for start in range(len(parts) - min_parts + 1):
            suffix = ".".join(parts[start:])
            index[suffix] = name if index.get(suffix, name) == name else None
    return index


class Project:
    def __init__(self) -> None:
        self.modules: dict[str, Module] = {}
        self.functions: dict[str, Function] = {}  # top-level functions, by dotted name
        self.every_function: list[Function] = []  # including methods and nested ones
        self.methods: dict[str, list[Function]] = {}  # methods, by bare method name
        self.classes: dict[str, Class] = {}  # by dotted name
        # Module-level `name = SomeClass()`: dotted variable name -> the
        # dotted name that was called, e.g. "app.db" -> "app.models.Database".
        self.instances: dict[str, str] = {}
        # Module-level string constants: "app.config.API_URL" -> "https://api.example.com/".
        self.constants: dict[str, str] = {}
        # Functions defined inside another function, by (enclosing function,
        # name). App factories put their views and helpers there.
        self.scoped: dict[tuple[int, str], Function] = {}
        # True if the app registers a before_request hook: login may be
        # enforced there, where the engine cannot see which routes it covers.
        self.has_request_hook = False
        self.skipped: list[tuple[str, str]] = []  # (file, reason)
        self.findings: dict[tuple[str, str, int], Finding] = {}
        self._top_level: set[str] = set()
        self._function_suffixes: dict[str, str | None] = {}
        self._module_suffixes: dict[str, str | None] = {}
        self._class_suffixes: dict[str, str | None] = {}
        self._instance_suffixes: dict[str, str | None] = {}
        self._constant_suffixes: dict[str, str | None] = {}

    # ---- loading ----------------------------------------------------

    @classmethod
    def from_path(cls, root: Path) -> "Project":
        project = cls()
        base = root.parent if root.is_file() else root
        for path in python_files(root):
            parts = list(path.relative_to(base).with_suffix("").parts)
            is_package = parts[-1] == "__init__"
            if is_package:
                parts = parts[:-1] or [base.name]
            try:
                source = path.read_text(encoding="utf-8")
                project.add_module(".".join(parts), source, str(path), is_package)
            except (
                OSError, UnicodeDecodeError, SyntaxError, ValueError, RecursionError, MemoryError
            ) as error:  # fmt: skip
                project.skipped.append((str(path), str(error)))
        return project

    def add_module(self, name: str, source: str, file: str, is_package: bool = False) -> None:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # scanned code's own SyntaxWarnings are not ours
            tree = ast.parse(source, filename=file)
        module = Module(name, file, tree, ImportMap(tree, name, is_package))
        self.modules[name] = module
        top_level = set(map(id, tree.body))
        owners = {  # function node -> the class it is defined directly inside
            id(member): f"{name}.{node.name}"
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef)
            for member in node.body
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                bases = [module.names.resolve(base) for base in node.bases]
                self.classes[f"{name}.{node.name}"] = Class(
                    f"{name}.{node.name}", [base for base in bases if base]
                )
        assigned: dict[str, int] = {}
        for node in tree.body:  # module-level `API_URL = "https://api.example.com/"`
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        assigned[target.id] = assigned.get(target.id, 0) + 1
                        value = node.value
                        if isinstance(value, ast.Constant) and isinstance(value.value, str):
                            module.constants[target.id] = value.value
        for constant in [c for c in module.constants if assigned[c] > 1]:
            del module.constants[constant]  # reassigned: not a constant after all
        for constant, text in module.constants.items():
            self.constants[f"{name}.{constant}"] = text
        for node in tree.body:  # module-level `db = Database()`
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                called = module.names.resolve(node.value.func)
                for target in node.targets:
                    if called and isinstance(target, ast.Name):
                        self.instances[f"{name}.{target.id}"] = called
        function_kinds = (ast.FunctionDef, ast.AsyncFunctionDef)
        parents = {  # function node -> the function it is defined directly inside
            id(member): id(node)
            for node in ast.walk(tree)
            if isinstance(node, function_kinds)
            for member in node.body
            if isinstance(member, function_kinds)
        }
        for node in ast.walk(tree):
            if isinstance(node, function_kinds):
                owner = owners.get(id(node))
                parent = parents.get(id(node))
                function = Function(f"{owner or name}.{node.name}", node, module, owner, parent=parent)
                self.every_function.append(function)
                if id(node) in top_level:
                    self.functions[function.name] = function
                elif owner and not node.name.startswith("__"):
                    self.methods.setdefault(node.name, []).append(function)
                elif parent is not None:
                    self.scoped[(parent, node.name)] = function
                hooks = {"before_request", "before_app_request"}
                if any(_decorator_name(d) in hooks for d in node.decorator_list):
                    self.has_request_hook = True

    # ---- name lookup ------------------------------------------------

    def _find(self, name: str | None, table: dict, suffixes: dict) -> str | None:
        """The key in `table` that a dotted name refers to, if there is one."""
        for _ in range(5):
            if not name:
                return None
            full = name if name in table else suffixes.get(name)
            if full:
                return full
            # Maybe a re-export: `from pkg import fetch` where pkg/__init__.py
            # has `from .client import fetch`. Follow that import.
            module_name, _, attribute = name.rpartition(".")
            module = self.modules.get(module_name) or self.modules.get(
                self._module_suffixes.get(module_name) or ""
            )
            target = module.names.aliases.get(attribute) if module else None
            if target is None or target == name:
                return None
            name = target
        return None

    def lookup(self, name: str) -> Function | None:
        """The project function a dotted name refers to, if there is one."""
        full = self._find(name, self.functions, self._function_suffixes)
        return self.functions[full] if full else None

    def class_name(self, name: str | None) -> str | None:
        """The class a dotted name refers to: a project class, or an outside
        class whose methods are sinks (requests.Session)."""
        if name in SINK_CLASSES or name in PATH_CLASSES:
            return name
        return self._find(name, self.classes, self._class_suffixes)

    def instance_type(self, name: str | None) -> str | None:
        """The class of a module-level object such as `db = Database()`."""
        full = self._find(name, self.instances, self._instance_suffixes)
        return self.class_name(self.instances[full]) if full else None

    def constant(self, name: str | None) -> str | None:
        """The text of a module-level string constant, given its dotted name."""
        full = self._find(name, self.constants, self._constant_suffixes)
        return self.constants[full] if full else None

    def is_internal(self, name: str) -> bool:
        """True if a dotted name points into this project, not a library."""
        first = name.split(".")[0]
        return first in self._top_level or first in self._module_suffixes

    def scoped_function(self, caller: Function, name: str) -> Function | None:
        """A function defined inside `caller`, or next to it inside the same
        enclosing function."""
        found = self.scoped.get((id(caller.node), name))
        if found is None and caller.parent is not None:
            found = self.scoped.get((caller.parent, name))
        return found

    def method_of(self, owner: str, method: str, depth: int = 0) -> Function | None:
        """The method `owner` (a class) uses for this name: its own, or the
        nearest one inherited from a base class in the project."""
        for function in self.methods.get(method, []):
            if function.owner == owner:
                return function
        if depth < 5 and owner in self.classes:
            for parent in self.classes[owner].bases:
                parent = self._find(parent, self.classes, self._class_suffixes)
                found = self.method_of(parent, method, depth + 1) if parent else None
                if found is not None:
                    return found
        return None

    def unique_method(self, method: str) -> Function | None:
        """`anything.method()`: a guess. We do not know the object's type, so
        this only answers when exactly one class in the project has a method
        with that name, and the name is not one built-in types also use."""
        # A mock in the test suite is never what the application calls.
        candidates = [
            function
            for function in self.methods.get(method, [])
            if not TEST_CODE.search(function.module.file)
        ]
        if len(candidates) == 1 and method not in BUILTIN_METHODS:
            return candidates[0]
        return None

    # ---- analysis ---------------------------------------------------

    def run(self) -> list[Finding]:
        self._function_suffixes = _suffix_index(self.functions, min_parts=2)
        self._module_suffixes = _suffix_index(self.modules, min_parts=1)
        self._class_suffixes = _suffix_index(self.classes, min_parts=2)
        self._instance_suffixes = _suffix_index(self.instances, min_parts=2)
        self._constant_suffixes = _suffix_index(self.constants, min_parts=2)
        self._top_level = {name.split(".")[0] for name in self.modules}

        # A function's result depends only on its own code and the summaries
        # of the functions it calls. So after the first round, a function is
        # analyzed again only if something it calls changed last round.
        callees: dict[int, set[int]] = {}
        changed_last: set[int] | None = None  # None: first round, analyze everything
        for _ in range(MAX_ROUNDS):
            changed_now: set[int] = set()
            for function in self.every_function:
                key = id(function)
                if changed_last is not None and not (callees.get(key, set()) & changed_last):
                    continue
                summary, used = self._analyze_function(function)
                callees[key] = used
                if summary != function.summary:
                    function.summary = summary
                    changed_now.add(key)
            if not changed_now:
                break
            changed_last = changed_now

        for module in self.modules.values():  # code outside any function
            tracker = Tracker(module, self, self.findings, Summary(), module.name)
            tracker.run_block(module.tree.body, {})

        return sorted(self.findings.values(), key=lambda f: (f.file, f.line, f.rule))

    def _analyze_function(self, function: Function) -> tuple[Summary, set[int]]:
        """Analyze one function. Returns its summary and the functions it called."""
        # Every parameter starts with a label naming itself, so we can see
        # where it ends up. URL parameters of a route are also really tainted.
        state = {param: from_param(param) for param in function.params}
        for param, kind in tainted_params(function.node).items():
            state[param] |= from_source(kind)
        summary = Summary()
        tracker = Tracker(function.module, self, self.findings, summary, function.name, function)
        try:
            tracker.run_block(function.node.body, state)
        except RecursionError:
            # An expression nested deeper than Python's stack allows (for
            # example thousands of chained "+"). Keep what we had.
            return function.summary, tracker.callees
        return summary, tracker.callees
