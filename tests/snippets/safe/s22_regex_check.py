# expect: none
import re

from flask import Flask, abort, request

app = Flask(__name__)


@app.route("/read")
def read():
    name = request.args["name"]
    if not re.match(r"^[a-z0-9_]+$", name):
        return "bad name", 400
    with open("/srv/files/" + name + ".txt") as f:
        return f.read()
