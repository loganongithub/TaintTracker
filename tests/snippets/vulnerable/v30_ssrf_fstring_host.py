# expect: ssrf line 12
import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/probe")
def probe():
    port = app.config["PROBE_PORT"]
    host = request.args["host"]
    return requests.get(f"http://{host}:{port}/status").text
