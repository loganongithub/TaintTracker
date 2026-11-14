# expect: path-traversal line 9
from flask import Flask, request, send_from_directory

app = Flask(__name__)


@app.route("/download")
def download():
    return send_from_directory(request.args["folder"], "report.pdf")
