# expect: none
import requests
from flask import Flask, abort, request

app = Flask(__name__)


@app.route("/fetch")
def fetch():
    url = "https://api.example.com/data"
    if request.args.get("debug"):
        url = request.args["url"]
        return "would fetch " + url
    return requests.get(url).text
