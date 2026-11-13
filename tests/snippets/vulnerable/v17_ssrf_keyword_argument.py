# expect: ssrf line 9
import requests
from flask import Flask, request

app = Flask(__name__)


def call(url, timeout):
    return requests.get(url, timeout=timeout).text


@app.route("/call")
def handler():
    return call(timeout=5, url=request.args["url"])
