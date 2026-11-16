# expect: none
from pathlib import Path

from flask import Flask, abort, request, send_file

app = Flask(__name__)
SAMPLES = Path("/srv/samples")


@app.route("/clip/<path:name>")
def clip(name):
    raw = Path(name)
    target = raw.resolve() if raw.is_absolute() else (SAMPLES / raw).resolve()
    if not target.is_relative_to(SAMPLES) or not target.is_file():
        abort(404)
    return send_file(target)
