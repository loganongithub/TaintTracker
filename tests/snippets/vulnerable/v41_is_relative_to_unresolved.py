# expect: path-traversal line 15
from pathlib import Path

from flask import Flask, abort, request, send_file

app = Flask(__name__)
SAMPLES = Path("/srv/samples")


@app.route("/clip/<path:name>")
def clip(name):
    target = SAMPLES / name
    if not target.is_relative_to(SAMPLES):
        abort(404)
    return send_file(target)
