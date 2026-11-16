# expect: low ssrf line 17
import requests
from flask import Flask, request

app = Flask(__name__)


def _is_safe_stream_url(url):
    return url.startswith("https://img.example.com/")


@app.route("/thumbnail")
def thumbnail():
    url = request.args.get("url", "").strip()
    if not _is_safe_stream_url(url):
        return "invalid", 400
    return requests.get(url).content
