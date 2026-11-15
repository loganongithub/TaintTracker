# expect: none
import io

from flask import Flask, request, send_file

app = Flask(__name__)


@app.route("/export")
def export():
    content = "name," + request.args["name"]
    return send_file(io.BytesIO(content.encode()), download_name="export.csv")
