# expect: ssrf line 14
import requests
from flask import Flask, request

app = Flask(__name__)


def requested_url():
    return request.args.get("url")


@app.route("/fetch")
def fetch():
    return requests.get(requested_url()).text
