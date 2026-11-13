# expect: path-traversal line 11
from flask import Flask, request

app = Flask(__name__)


@app.route("/read")
def read():
    path = "/srv/files/"
    path += request.args["name"]
    with open(path) as f:
        return f.read()
