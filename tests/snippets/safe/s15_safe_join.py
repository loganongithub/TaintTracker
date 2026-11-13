# expect: none
from flask import Flask, send_file
from werkzeug.utils import safe_join

app = Flask(__name__)


@app.route("/files/<path:name>")
def files(name):
    return send_file(safe_join("/srv/files", name))
