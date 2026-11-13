"""Turns a call target like `http.get` into a full name like "requests.get"."""

import ast


class ImportMap:
    """Remembers what each name in one module really refers to."""

    def __init__(self, tree: ast.Module, module: str = "", is_package: bool = False):
        self.module = module
        self.aliases: dict[str, str] = {}
        # Names bound by a plain `import x`: these are modules for certain,
        # so `x.f()` is a function call, never a method call on an object.
        self.imported_modules: set[str] = set()
        # Functions defined at the top of this module: `helper` means
        # "<this module>.helper".
        self.local = {
            node.name
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }

        package = module.split(".") if module else []
        if not is_package:
            package = package[:-1]  # shop.views lives in package shop

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.imported_modules.add(alias.asname or alias.name.split(".")[0])
                    if alias.asname:  # import requests as http
                        self.aliases[alias.asname] = alias.name
            elif isinstance(node, ast.ImportFrom):
                if node.level:  # from .storage import x, from . import storage
                    base = package[: len(package) - (node.level - 1)]
                    prefix = ".".join([*base, *filter(None, [node.module])])
                else:
                    prefix = node.module or ""
                for alias in node.names:  # from flask import request as req
                    target = f"{prefix}.{alias.name}" if prefix else alias.name
                    self.aliases[alias.asname or alias.name] = target

    def resolve(self, node: ast.AST) -> str | None:
        """Full dotted name of a Name/Attribute chain, or None if it has no fixed name.

        `req.args.get` -> "flask.request.args.get"
        `get_client().fetch` -> None
        """
        parts: list[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if not isinstance(node, ast.Name):
            return None
        if node.id in self.aliases:
            root = self.aliases[node.id]
        elif node.id in self.local and self.module:
            root = f"{self.module}.{node.id}"
        elif node.id == "request":  # not imported in this file: assume Flask's
            root = "flask.request"
        else:
            root = node.id
        return ".".join([root, *reversed(parts)])
