# expect: low path-traversal line 17
import os
import tempfile

from flask import Flask, abort, request

app = Flask(__name__)


@app.route("/transcribe", methods=["POST"])
def transcribe():
    upload = request.files["audio"]
    suffix = os.path.splitext(upload.filename)[1]
    tmp = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
    tmp.write(upload.read())
    tmp.close()
    os.unlink(tmp.name)
    return "done"
