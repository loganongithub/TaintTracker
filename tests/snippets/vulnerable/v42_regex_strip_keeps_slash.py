# expect: path-traversal line 12
import re

from flask import Flask, abort, request

app = Flask(__name__)


@app.route("/report", methods=["POST"])
def report():
    page_id = re.sub(r"[^a-zA-Z0-9_./\-]", "", str(request.json.get("page_id", "")))
    with open("/srv/perf/" + page_id + ".json", "w") as f:
        f.write("{}")
    return "saved"
