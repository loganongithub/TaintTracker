# expect: path-traversal line 19
import os

from flask import Flask, abort, request

app = Flask(__name__)
UPLOADS = "/srv/uploads"


def allowed_file(name):
    return name.rsplit(".", 1)[-1].lower() in {"png", "jpg"}


@app.route("/image")
def image():
    name = request.args["name"]
    if not allowed_file(name):
        abort(400)
    with open(os.path.join(UPLOADS, name), "rb") as f:
        return f.read()
