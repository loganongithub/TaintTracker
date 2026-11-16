# expect: path-traversal line 11, path-traversal line 14
from flask import Flask, abort, request

app = Flask(__name__)


@app.route("/report", methods=["POST"])
def report():
    kind = request.json["type"]
    first = "/srv/reports/" + kind + "_report.json"
    with open(first, "w") as f:
        f.write("{}")
    second = f"/srv/reports/{kind}-2026.json"
    with open(second, "w") as f:
        f.write("{}")
    return "saved"
