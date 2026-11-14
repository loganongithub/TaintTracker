# expect: none
import os

from flask import Flask, abort, request

app = Flask(__name__)
BASE = "/srv/files"


@app.route("/read")
def read():
    path = os.path.realpath(os.path.join(BASE, request.args["name"]))
    if not path.startswith(BASE + os.sep):
        abort(403)
    with open(path) as f:
        return f.read()
