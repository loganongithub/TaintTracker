# expect: ssrf line 11
import requests
from flask import Flask, abort, request

app = Flask(__name__)


@app.route("/notify", methods=["POST"])
def notify():
    with requests.Session() as client:
        client.post(request.form["callback"], json={"ok": True})
    return "sent"
