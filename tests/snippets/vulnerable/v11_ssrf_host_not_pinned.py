# expect: ssrf line 11
import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/api")
def api():
    path = request.args.get("path")
    return requests.get("https://api.example.com" + path).text
