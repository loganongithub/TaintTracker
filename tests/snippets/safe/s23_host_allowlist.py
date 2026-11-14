# expect: none
from urllib.parse import urlparse

import requests
from flask import Flask, abort, request

app = Flask(__name__)
ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}


@app.route("/fetch")
def fetch():
    url = request.args["url"]
    host = urlparse(url).hostname
    if host not in ALLOWED_HOSTS:
        abort(400)
    return requests.get(url).text
