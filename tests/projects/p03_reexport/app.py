# expect: none
from flask import Flask, request

from net import fetch

app = Flask(__name__)


@app.route("/fetch")
def handler():
    return fetch(request.args["url"])
