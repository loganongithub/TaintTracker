# expect: none
from flask import Flask, request

import helpers as h

app = Flask(__name__)


@app.route("/read")
def read():
    return h.load(request.args["name"])
