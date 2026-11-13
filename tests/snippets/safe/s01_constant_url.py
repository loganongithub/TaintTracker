# expect: none
import requests
from flask import Flask

app = Flask(__name__)


@app.route("/health")
def health():
    return requests.get("https://status.example.com/ping").text
