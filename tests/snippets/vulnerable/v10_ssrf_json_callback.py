# expect: ssrf line 11
import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/notify", methods=["POST"])
def notify():
    data = request.get_json()
    requests.post(data["callback"], json={"ok": True})
    return "sent"
