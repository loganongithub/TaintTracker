# expect: path-traversal line 10
from flask import Flask, request

app = Flask(__name__)


@app.route("/read")
def read():
    folder, name = "/srv/files/", request.args["name"]
    with open(folder + name) as f:
        return f.read()
