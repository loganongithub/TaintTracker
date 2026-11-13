# expect: path-traversal line 12
from flask import Flask, request

app = Flask(__name__)


class Reports:
    def load(self, name):
        return self._read("/srv/reports/" + name)

    def _read(self, path):
        with open(path) as f:
            return f.read()


class Cache:
    def _read(self, key):
        return None


@app.route("/report")
def report():
    return Reports().load(request.args["name"])
