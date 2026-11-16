# expect: low path-traversal line 11, low path-traversal line 14
from flask import Flask, abort, request

app = Flask(__name__)


@app.route("/report", methods=["POST"])
def report():
    kind = request.json["type"]
    first = "/srv/reports/report_" + kind + ".json"
    with open(first, "w") as f:
        f.write("{}")
    second = f"/srv/reports/2026-01-01_{kind}.json"
    with open(second, "w") as f:
        f.write("{}")
    return "saved"
