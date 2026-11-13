# expect: ssrf line 11
import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/fetch")
def fetch():
    url = request.args.get("url").strip()
    return requests.get(url).text
