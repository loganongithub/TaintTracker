# expect: ssrf line 11
import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/probe")
def probe():
    scheme = "https" if request.args.get("tls") == "1" else "http"
    return requests.get(scheme + "://" + request.args["host"] + "/status").text
