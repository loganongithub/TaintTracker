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
SINKS: dict[str, tuple[str, int, str]] = {
    **{f"requests.{verb}": (SSRF, 0, "url") for verb in _HTTP_VERBS},
    **{f"httpx.{verb}": (SSRF, 0, "url") for verb in _HTTP_VERBS},
    "requests.request": (SSRF, 1, "url"),
    "httpx.request": (SSRF, 1, "url"),
    "urllib.request.urlopen": (SSRF, 0, "url"),
    "urllib.request.urlretrieve": (SSRF, 0, "url"),
    "open": (PATH_TRAVERSAL, 0, "file"),
    "io.open": (PATH_TRAVERSAL, 0, "file"),
    "flask.send_file": (PATH_TRAVERSAL, 0, "path_or_file"),
    "os.remove": (PATH_TRAVERSAL, 0, "path"),
    "os.unlink": (PATH_TRAVERSAL, 0, "path"),
    "os.rmdir": (PATH_TRAVERSAL, 0, "path"),
    "os.listdir": (PATH_TRAVERSAL, 0, "path"),
    "shutil.rmtree": (PATH_TRAVERSAL, 0, "path"),
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
}
