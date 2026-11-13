# expect: ssrf line 13
import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/proxy")
def proxy():
    host = request.args.get("host")
    base = "https://" + host
    target = base + "/status"
    resp = requests.get(target)
    return resp.text
