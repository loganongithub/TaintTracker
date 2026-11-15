"""Sources, sinks and sanitizers, as plain data.

All names are fully qualified, after imports have been resolved
(see engine/names.py), so `from flask import send_file` and
`flask.send_file` both match "flask.send_file".
"""

from taintscan.finding import PATH_TRAVERSAL, SSRF

# Attributes of flask.request that carry attacker-controlled data.
REQUEST_SOURCES = {
    "args", "form", "values", "json", "data", "headers", "cookies",
    "files", "view_args", "get_json", "get_data",
}

# Route converters whose output cannot carry a hostname or "../".
SAFE_CONVERTERS = {"int", "float", "uuid"}

# Sinks are argument-specific: name -> (rule, positional index, keyword name).
# Only that one argument is checked.
_HTTP_VERBS = ("get", "post", "put", "patch", "delete", "head", "options")

# Classes whose instances make requests: `s = requests.Session(); s.get(url)`.
# The engine tracks which variables hold one (see tracker.py).
_HTTP_CLIENTS = ("requests.Session", "requests.sessions.Session", "httpx.Client")

SINKS: dict[str, tuple[str, int, str]] = {
    **{f"requests.{verb}": (SSRF, 0, "url") for verb in _HTTP_VERBS},
    **{f"httpx.{verb}": (SSRF, 0, "url") for verb in _HTTP_VERBS},
    **{f"{client}.{verb}": (SSRF, 0, "url") for client in _HTTP_CLIENTS for verb in _HTTP_VERBS},
    **{f"{client}.request": (SSRF, 1, "url") for client in _HTTP_CLIENTS},
    "requests.request": (SSRF, 1, "url"),
    "httpx.request": (SSRF, 1, "url"),
    "urllib3.PoolManager.request": (SSRF, 1, "url"),
    "urllib.request.urlopen": (SSRF, 0, "url"),
    "urllib.request.urlretrieve": (SSRF, 0, "url"),
    "open": (PATH_TRAVERSAL, 0, "file"),
    "io.open": (PATH_TRAVERSAL, 0, "file"),
    "codecs.open": (PATH_TRAVERSAL, 0, "filename"),
    "flask.send_file": (PATH_TRAVERSAL, 0, "path_or_file"),
    # send_from_directory protects the file name, not the directory.
    "flask.send_from_directory": (PATH_TRAVERSAL, 0, "directory"),
    "os.remove": (PATH_TRAVERSAL, 0, "path"),
    "os.unlink": (PATH_TRAVERSAL, 0, "path"),
    "os.rmdir": (PATH_TRAVERSAL, 0, "path"),
    "os.listdir": (PATH_TRAVERSAL, 0, "path"),
    "shutil.rmtree": (PATH_TRAVERSAL, 0, "path"),
    "shutil.copy": (PATH_TRAVERSAL, 0, "src"),
    "shutil.copyfile": (PATH_TRAVERSAL, 0, "src"),
    "shutil.move": (PATH_TRAVERSAL, 0, "src"),
}

# Classes worth remembering the type of: the first part of a SINKS key
# such as "requests.Session.get".
SINK_CLASSES = {*_HTTP_CLIENTS, "urllib3.PoolManager"}

# Methods that are a sink when called on a tainted value, whatever its type.
# These names are specific to pathlib: Path(user_input).read_text().
RECEIVER_SINKS: dict[str, str] = {
    "read_text": PATH_TRAVERSAL,
    "read_bytes": PATH_TRAVERSAL,
    "write_text": PATH_TRAVERSAL,
    "write_bytes": PATH_TRAVERSAL,
}

# Calls whose result is safe for every bug class.
CLEANERS = {"int", "float", "bool", "len", "hash", "uuid.UUID"}

# Calls whose result is safe for one bug class only: name -> rule removed.
SANITIZERS: dict[str, str] = {
    "os.path.basename": PATH_TRAVERSAL,
    "werkzeug.utils.secure_filename": PATH_TRAVERSAL,
    # safe_join raises NotFound if the result would leave the base directory.
    "flask.safe_join": PATH_TRAVERSAL,
    "werkzeug.utils.safe_join": PATH_TRAVERSAL,
    "werkzeug.security.safe_join": PATH_TRAVERSAL,
    # An in-memory buffer is not a path: send_file(io.BytesIO(data)) reads no file.
    "io.BytesIO": PATH_TRAVERSAL,
    "io.StringIO": PATH_TRAVERSAL,
}

# Calls that resolve a path. Their result can be checked with startswith().
NORMALIZERS = {"os.path.realpath", "os.path.abspath", "os.path.normpath"}

# Calls that leave the current function, so code after them does not run.
EXIT_CALLS = {"flask.abort", "werkzeug.exceptions.abort", "abort", "sys.exit", "exit", "quit"}

# Calls that test a string against a pattern.
REGEX_CHECKS = {"re.match", "re.fullmatch"}

# urlparse(url).netloc and friends: the part of a URL an allowlist should check.
URL_PARSERS = {"urllib.parse.urlparse", "urllib.parse.urlsplit", "urlparse.urlparse"}
URL_HOST_ATTRIBUTES = {"netloc", "hostname", "host"}
