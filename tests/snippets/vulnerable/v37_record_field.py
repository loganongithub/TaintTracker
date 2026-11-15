# expect: path-traversal line 16
from flask import Flask, abort, request

app = Flask(__name__)


class Instance:
    def __init__(self, name):
        self.name = name
        self.id = None


@app.route("/instance", methods=["POST"])
def create():
    instance = Instance(request.form["name"])
    with open(f"/srv/conf/{instance.name}.conf", "w") as f:
        f.write("ok")
    return "created"
