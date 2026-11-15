# expect: ssrf line 10, ssrf line 11
import requests
from flask import Flask, abort, request

app = Flask(__name__)


@app.route("/follow")
def follow():
    first = requests.get(request.args["url"]).json()
    return requests.get(first["next"]).text
