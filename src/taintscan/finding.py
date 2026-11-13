"""The one data type the engine hands to everything else."""

from dataclasses import dataclass

SSRF = "ssrf"
PATH_TRAVERSAL = "path-traversal"


@dataclass(frozen=True)
class Finding:
    rule: str  # SSRF or PATH_TRAVERSAL
    file: str
    line: int  # line of the sink call
    message: str = ""
