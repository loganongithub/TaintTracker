# expect: low path-traversal line 12
from flask import Flask, abort, request

app = Flask(__name__)


@app.route("/read")
def read():
    name = request.args["name"]
    if ".." in name or "/" in name:
        abort(400)
    with open("/srv/files/" + name) as f:
        return f.read()
