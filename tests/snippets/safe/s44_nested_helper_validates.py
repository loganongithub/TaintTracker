# expect: low path-traversal line 18
from flask import Flask, abort, send_file

import safepath


def create_app(root):
    app = Flask(__name__)

    def file_for(sub):
        try:
            return safepath.resolve_within(root, sub)
        except safepath.PathError:
            abort(404)

    @app.route("/d/<path:sub>")
    def download(sub):
        return send_file(file_for(sub))

    return app
