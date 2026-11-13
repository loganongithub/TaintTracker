# expect: none
import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    url = "https://api.example.com/v1/items"
    return requests.get(url).text
