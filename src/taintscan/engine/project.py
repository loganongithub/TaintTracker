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

from taintscan.engine.model import Function, Module, Summary
from taintscan.engine.names import ImportMap
from taintscan.engine.routes import tainted_params
from taintscan.engine.taint import FROM_SOURCE, from_param
from taintscan.engine.tracker import Tracker
from taintscan.finding import Finding

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
        self.skipped: list[tuple[str, str]] = []  # (file, reason)
        self.findings: dict[tuple[str, str, int], Finding] = {}
        self._function_suffixes: dict[str, str | None] = {}
        self._module_suffixes: dict[str, str | None] = {}

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
            except (OSError, UnicodeDecodeError, SyntaxError, ValueError) as error:
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
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                owner = owners.get(id(node))
                function = Function(f"{owner or name}.{node.name}", node, module, owner)
                self.every_function.append(function)
                if id(node) in top_level:
                    self.functions[function.name] = function
                elif owner and not node.name.startswith("__"):
                    self.methods.setdefault(node.name, []).append(function)

    # ---- name lookup ------------------------------------------------

    def lookup(self, name: str) -> Function | None:
        """The project function a dotted name refers to, if there is one."""
        for _ in range(5):
            full = name if name in self.functions else self._function_suffixes.get(name)
            if full:
                return self.functions[full]
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

    def method_of(self, owner: str, method: str) -> Function | None:
        """`self.method()` inside class `owner`: the method that class defines."""
        for function in self.methods.get(method, []):
            if function.owner == owner:
                return function
        return None

    def unique_method(self, method: str) -> Function | None:
        """`anything.method()`: a guess. We do not know the object's type, so
        this only answers when exactly one class in the project has a method
        with that name, and the name is not one built-in types also use."""
        candidates = self.methods.get(method, [])
        if len(candidates) == 1 and method not in BUILTIN_METHODS:
            return candidates[0]
        return None

    # ---- analysis ---------------------------------------------------

    def run(self) -> list[Finding]:
        self._function_suffixes = _suffix_index(self.functions, min_parts=2)
        self._module_suffixes = _suffix_index(self.modules, min_parts=1)

        for _ in range(MAX_ROUNDS):
            changed = False
            for function in self.every_function:
                summary = self._analyze_function(function)
                if summary != function.summary:
                    function.summary = summary
                    changed = True
            if not changed:
                break

        for module in self.modules.values():  # code outside any function
            tracker = Tracker(module, self, self.findings, Summary(), module.name)
            tracker.run_block(module.tree.body, {})

        return sorted(self.findings.values(), key=lambda f: (f.file, f.line, f.rule))

    def _analyze_function(self, function: Function) -> Summary:
        # Every parameter starts with a label naming itself, so we can see
        # where it ends up. URL parameters of a route are also really tainted.
        state = {param: from_param(param) for param in function.params}
        for param in tainted_params(function.node):
            state[param] |= FROM_SOURCE
        summary = Summary()
        tracker = Tracker(
            function.module, self, self.findings, summary, function.name, function.owner
        )
        tracker.run_block(function.node.body, state)
        return summary
