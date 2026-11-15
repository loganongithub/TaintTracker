# expect: path-traversal line 12
import os
import tempfile

from flask import Flask, abort, request

app = Flask(__name__)


@app.route("/cleanup")
def cleanup():
    os.unlink(os.path.join(tempfile.gettempdir(), request.args["name"]))
    return "done"
