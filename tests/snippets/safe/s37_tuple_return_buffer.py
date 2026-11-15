# expect: none
import io

from flask import Flask, request, send_file

app = Flask(__name__)


def build_report(title):
    buffer = io.BytesIO()
    buffer.write(title.encode())
    return buffer, title + ".csv"


@app.route("/report")
def report():
    output, filename = build_report(request.args["title"])
    return send_file(output, download_name=filename)
