# expect: none
import requests
from flask import Flask, request

app = Flask(__name__)


def call(url, timeout):
    return requests.get(url, timeout=timeout).text


@app.route("/call")
def handler():
    return call(timeout=request.args["t"], url="https://api.example.com/x")
