# expect: path-traversal line 11
from pathlib import Path

from flask import Flask, abort, request

app = Flask(__name__)


@app.route("/read")
def read():
    return Path("/srv/files", request.args["name"]).read_text()
