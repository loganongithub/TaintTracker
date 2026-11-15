# expect: none
from pathlib import Path

from flask import Flask, abort, request

app = Flask(__name__)
NOTES = Path("/srv/notes")


@app.route("/note/<path:filename>")
def note(filename):
    safe_name = Path(filename).name
    return (NOTES / safe_name).read_text()
