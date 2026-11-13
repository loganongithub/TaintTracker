# expect: ssrf line 14
import requests
from flask import Flask, request

app = Flask(__name__)


def build_url(host):
    return "https://" + host + "/status"


@app.route("/status")
def status():
    return requests.get(build_url(request.args["host"])).text
