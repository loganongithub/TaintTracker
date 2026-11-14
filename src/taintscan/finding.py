"""The one data type the engine hands to everything else."""

from dataclasses import dataclass

SSRF = "ssrf"
PATH_TRAVERSAL = "path-traversal"

HIGH = "high"
LOW = "low"


@dataclass(frozen=True)
class Finding:
    rule: str  # SSRF or PATH_TRAVERSAL
    file: str
    line: int  # line of the sink call
    message: str = ""
    # LOW: the attacker only chose which stored value reaches the sink
    # (a lookup by id, a dict key), not the value's content.
    confidence: str = HIGH
