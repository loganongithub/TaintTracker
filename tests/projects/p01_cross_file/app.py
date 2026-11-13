# expect: none
from flask import Flask, request

from utils import download

app = Flask(__name__)


@app.route("/fetch")
def fetch():
    return download(request.args.get("url"))
