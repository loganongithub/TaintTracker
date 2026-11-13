# expect: none
from flask import Flask, request

app = Flask(__name__)


class Store:
    def get(self, key):
        with open(key) as f:
            return f.read()


labels = {}


@app.route("/label")
def label():
    return labels.get(request.args["name"], "unknown")
