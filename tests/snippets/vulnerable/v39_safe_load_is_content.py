# expect: ssrf line 13
import yaml

import requests
from flask import Flask, abort, request

app = Flask(__name__)


@app.route("/import", methods=["POST"])
def import_config():
    config = yaml.safe_load(request.data)
    return requests.get(config["source"]).text
