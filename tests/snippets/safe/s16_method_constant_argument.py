# expect: none
import requests
from flask import Flask, request

app = Flask(__name__)


class Fetcher:
    def send(self, base_url):
        return requests.get(base_url)


@app.route("/fetch")
def fetch():
    label = request.args.get("label")
    return label + Fetcher().send("https://api.example.com/data").text
