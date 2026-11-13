# expect: none
import os

from flask import Flask, request
from werkzeug.utils import secure_filename

app = Flask(__name__)


@app.route("/read")
def read():
    name = secure_filename(request.args["name"])
    with open(os.path.join("/srv/files", name)) as f:
        return f.read()
