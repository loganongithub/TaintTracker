# expect: none
from flask import Flask, request

app = Flask(__name__)


def pick(name):
    return "/srv/files/default.txt"


@app.route("/read")
def read():
    with open(pick(request.args["name"])) as f:
        return f.read()
