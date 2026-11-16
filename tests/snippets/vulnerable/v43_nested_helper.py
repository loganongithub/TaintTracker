# expect: path-traversal line 9
from flask import Flask, request


def create_app():
    app = Flask(__name__)

    def read(path):
        with open(path) as f:
            return f.read()

    @app.route("/read")
    def view():
        return read("/srv/files/" + request.args["name"])

    return app
