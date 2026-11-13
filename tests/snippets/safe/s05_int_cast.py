# expect: none
from flask import Flask, request

app = Flask(__name__)


@app.route("/report")
def report():
    report_id = int(request.args["id"])
    with open(f"/srv/reports/{report_id}.txt") as f:
        return f.read()
