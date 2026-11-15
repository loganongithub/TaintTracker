# expect: low ssrf line 12
import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/upload", methods=["POST"])
def upload():
    name = request.form["name"]
    url = f"{app.config['LIBRARY_URL']}/add-book/{name}"
    return requests.post(url).text
