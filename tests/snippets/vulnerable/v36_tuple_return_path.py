# expect: path-traversal line 14
from flask import Flask, request, send_file

app = Flask(__name__)


def locate(name):
    return "/srv/files/" + name, "text/plain"


@app.route("/file")
def file():
    path, mimetype = locate(request.args["name"])
    return send_file(path, mimetype=mimetype)
