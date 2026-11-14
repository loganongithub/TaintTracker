# expect: none
from flask import Flask, abort, request

app = Flask(__name__)
ALLOWED = ("readme.txt", "licence.txt")


@app.route("/read")
def read():
    name = request.args["name"]
    if name in ALLOWED:
        with open("/srv/files/" + name) as f:
            return f.read()
    return "not found", 404
