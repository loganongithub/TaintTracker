# expect: none
import os

from flask import Flask, request
from werkzeug.utils import secure_filename

app = Flask(__name__)


def clean(name):
    return secure_filename(name)


@app.route("/read")
def read():
    with open(os.path.join("/srv/files", clean(request.args["name"]))) as f:
        return f.read()
