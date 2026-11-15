# expect: low path-traversal line 19
import os

from flask import Flask, abort, request

app = Flask(__name__)
BASE = "/srv/files"


def is_safe_path(path):
    return os.path.commonpath([BASE, os.path.realpath(path)]) == BASE


@app.route("/read")
def read():
    path = os.path.join(BASE, request.args["name"])
    if not is_safe_path(path):
        abort(400)
    with open(path) as f:
        return f.read()
