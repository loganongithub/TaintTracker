# expect: none
from flask import Flask, request

app = Flask(__name__)


@app.route("/read")
def read():
    path, name = "/srv/files/readme.txt", request.args["name"]
    with open(path) as f:
        return name + f.read()
