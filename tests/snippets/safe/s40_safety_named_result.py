# expect: low ssrf line 17
import requests
from flask import Flask, abort, request

app = Flask(__name__)


def validate_outbound_url(url):
    if not url.startswith("https://"):
        raise ValueError("https only")
    return url


@app.route("/check")
def check():
    target = validate_outbound_url(request.args["url"])
    return requests.get(target).text
