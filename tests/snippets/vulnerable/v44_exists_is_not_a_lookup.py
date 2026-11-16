# expect: path-traversal line 15
import os

from flask import Flask, abort, request

app = Flask(__name__)


@app.route("/attach", methods=["POST"])
def attach():
    job_id = request.form["job_id"]
    found = os.path.isdir("/srv/jobs/" + job_id)
    if not found:
        return "unknown job", 404
    with open("/srv/jobs/" + job_id + "/manifest.json") as f:
        return f.read()
