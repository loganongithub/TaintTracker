# expect: ssrf line 17
from urllib.parse import urlparse

import requests
from flask import Flask, abort, request

app = Flask(__name__)
BLOCKED = {"localhost", "127.0.0.1"}


@app.route("/fetch")
def fetch():
    url = request.args["url"]
    host = urlparse(url).hostname
    if host in BLOCKED:
        abort(400)
    return requests.get(url).text
