# expect: none
import requests
from flask import Flask, request

app = Flask(__name__)


def download(url):
    return requests.get(url).text


@app.route("/fetch")
def fetch():
    label = request.args.get("label")
    return label + download("https://api.example.com/data")
