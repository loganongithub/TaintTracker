"""The data types the engine hands to everything else."""

from dataclasses import dataclass

SSRF = "ssrf"
PATH_TRAVERSAL = "path-traversal"

HIGH = "high"
LOW = "low"

# Where the untrusted data came from.
FROM_REQUEST = "request"  # request.args, request.form, request.json, ...
FROM_PATH_PARAM = "route-path"  # a <path:name> URL parameter: may contain "/"
FROM_URL_PARAM = "route"  # a plain <name> URL parameter: cannot contain "/"


@dataclass(frozen=True)
class Entry:
    """One way untrusted data gets to a sink: the function where it enters."""

    function: str  # dotted name of the function that reads the untrusted data
    file: str
    line: int  # the sink itself, or the call that passes the data on
    source: str  # FROM_REQUEST, FROM_PATH_PARAM or FROM_URL_PARAM
    depth: int = 0  # calls between that function and the sink
    route: bool = False  # the function is a Flask view
    auth: str = "none"  # "none", "login" or "admin", judged from decorator names
    guarded: bool = False  # a validator-looking function is called along the way


@dataclass(frozen=True)
class Finding:
    rule: str  # SSRF or PATH_TRAVERSAL
    file: str
    line: int  # line of the sink call
    message: str = ""
    # LOW: the attacker's control is partial. They only chose which stored
    # value reaches the sink (a lookup by id, a dict key), or only the end
    # of a URL whose start came from configuration.
    confidence: str = HIGH
    entries: tuple[Entry, ...] = ()  # every place the data can come in from
