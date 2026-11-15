# expect: path-traversal line 12
from pathlib import Path

from flask import Flask, abort, request

app = Flask(__name__)
NOTES = Path("/srv/notes")


@app.route("/note/<path:filename>")
def note(filename):
    return (NOTES / filename).read_text()
