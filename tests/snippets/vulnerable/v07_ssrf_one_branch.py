# expect: ssrf line 13
import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/fetch")
def fetch():
    url = "https://api.example.com/default"
    if request.args.get("custom"):
        url = request.args.get("url")
    return requests.get(url).text
