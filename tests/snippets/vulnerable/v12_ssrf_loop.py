# expect: ssrf line 12
import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/check", methods=["POST"])
def check():
    results = []
    for url in request.get_json()["urls"]:
        results.append(requests.get(url).status_code)
    return {"codes": results}
