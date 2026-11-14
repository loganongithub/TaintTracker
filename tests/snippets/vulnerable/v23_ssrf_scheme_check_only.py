# expect: ssrf line 15
from urllib.parse import urlparse

import requests
from flask import Flask, abort, request

app = Flask(__name__)


@app.route("/fetch")
def fetch():
    url = request.args["url"]
    if urlparse(url).scheme not in ("http", "https"):
        abort(400)
    return requests.get(url).text
