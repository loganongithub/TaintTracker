# expect: path-traversal line 10
from flask import Flask, request

app = Flask(__name__)


@app.route("/upload", methods=["POST"])
def upload_file():
    upload = request.files["file"]
    upload.save("/srv/uploads/" + request.form["folder"] + "/data.bin")
    return "saved"
