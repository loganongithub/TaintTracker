# expect: none
from flask import Flask, request

import helpers as h

app = Flask(__name__)


@app.route("/read")
def read():
    with open(h.safe_path(request.args["name"])) as f:
        return f.read()
