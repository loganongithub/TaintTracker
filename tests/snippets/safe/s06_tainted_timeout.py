# expect: none
import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/slow")
def slow():
    seconds = request.args.get("timeout")
    return requests.get("https://api.example.com/slow", timeout=seconds).text
