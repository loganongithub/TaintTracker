# expect: path-traversal line 8
from flask import Flask, request

app = Flask(__name__)


def read(path):
    with open(path) as f:
        return f.read()


def load_report(name):
    return read("/srv/reports/" + name)


@app.route("/report")
def report():
    return load_report(request.args["name"])
