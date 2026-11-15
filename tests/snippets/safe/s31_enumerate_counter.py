# expect: none
import os

from flask import Flask, request

app = Flask(__name__)


@app.route("/photos", methods=["POST"])
def photos():
    for index, upload in enumerate(request.files.getlist("photos")):
        with open(os.path.join("/srv/photos", f"page{index}.jpg"), "wb") as f:
            f.write(upload.read())
    return "saved"
