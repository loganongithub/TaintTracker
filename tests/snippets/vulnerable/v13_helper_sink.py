# expect: ssrf line 9
import requests
from flask import Flask, request

app = Flask(__name__)


def download(url):
    return requests.get(url).text


@app.route("/fetch")
def fetch():
    return download(request.args.get("url"))
