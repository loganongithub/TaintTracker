# expect: low ssrf line 11
import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/editor")
def editor():
    name = request.args["q"]
    return requests.get(app.config["API_BASE_URL"] + "ws/editor/?q=" + name).text
