# expect: path-traversal line 10
from flask import Flask, abort, request

app = Flask(__name__)
TEMPLATE = "/srv/reports/{}.txt"


@app.route("/report")
def report():
    with open(TEMPLATE.format(request.args["name"])) as f:
        return f.read()
