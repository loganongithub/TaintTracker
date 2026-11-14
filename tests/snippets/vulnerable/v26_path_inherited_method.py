# expect: path-traversal line 9
from flask import Flask, abort, request

app = Flask(__name__)


class Store:
    def read(self, path):
        with open(path) as f:
            return f.read()


class Reports(Store):
    def load(self, name):
        return self.read("/srv/reports/" + name)


class Cache:
    def read(self, key):
        return None

    def load(self, key):
        return None


@app.route("/report")
def report():
    reports = Reports()
    return reports.load(request.args["name"])
