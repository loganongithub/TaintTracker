# expect: ssrf line 11
import requests
from flask import Flask, abort, request

app = Flask(__name__)
SCHEME = "https://"


@app.route("/probe")
def probe():
    return requests.get(SCHEME + request.args["host"]).text
