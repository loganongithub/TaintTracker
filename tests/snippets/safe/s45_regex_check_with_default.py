# expect: none
import re

from flask import Flask, abort, request

app = Flask(__name__)
TOKEN = re.compile(r"[0-9a-f]{32}")


@app.route("/table", methods=["POST"])
def table():
    token = request.json.get("token")
    if not re.fullmatch(r"[0-9a-f]{32}", token or ""):
        abort(400)
    with open(f"/srv/work/{token}.json") as f:
        return f.read()


@app.route("/upload/<path:token>")
def upload(token):
    if not TOKEN.match(token or ""):
        abort(404)
    with open("/srv/work/" + token + ".part") as f:
        return f.read()
