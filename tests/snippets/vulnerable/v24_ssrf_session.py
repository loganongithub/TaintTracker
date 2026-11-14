# expect: ssrf line 11
import requests
from flask import Flask, abort, request

app = Flask(__name__)


@app.route("/fetch")
def fetch():
    session = requests.Session()
    return session.get(request.args["url"]).text
