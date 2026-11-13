# expect: path-traversal line 12
import os

from flask import Flask

app = Flask(__name__)


@app.route("/files/<path:name>")
def read_file(name):
    path = os.path.join("/srv/files", name)
    with open(path) as f:
        return f.read()
