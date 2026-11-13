# expect: none
import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/search")
def search():
    query = request.args.get("q")
    resp = requests.get("https://api.example.com/search")
    return str(len(query)) + resp.text
