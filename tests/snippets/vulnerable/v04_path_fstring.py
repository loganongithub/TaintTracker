# expect: path-traversal line 10
from flask import Flask, request, send_file

app = Flask(__name__)


@app.route("/download", methods=["POST"])
def download():
    name = request.form["name"]
    return send_file(f"/srv/reports/{name}.pdf")
