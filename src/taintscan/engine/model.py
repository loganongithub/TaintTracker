"""The records the engine keeps about a project: modules, functions, summaries."""

import ast
from dataclasses import dataclass, field

from taintscan.engine.names import ImportMap
from taintscan.engine.taint import CLEAN, Taint


@dataclass(frozen=True)
class SinkHit:
    """A sink call that some value reaches."""

    rule: str
    file: str
    line: int
    sink: str  # e.g. "requests.get"
    argument: str  # e.g. "url"


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


@dataclass
class Module:
    name: str  # dotted, e.g. "shop.views"
    file: str
    tree: ast.Module
    names: ImportMap


@dataclass
class Function:
    name: str  # dotted, e.g. "shop.storage.read_upload"
    node: ast.FunctionDef | ast.AsyncFunctionDef
    module: Module
    owner: str | None = None  # dotted name of the class, if this is a method
    summary: Summary = field(default_factory=Summary)

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
