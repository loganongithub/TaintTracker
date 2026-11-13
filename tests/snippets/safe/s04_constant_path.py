# expect: none
from flask import Flask, request

app = Flask(__name__)


@app.route("/readme")
def readme():
    lang = request.args.get("lang", "en")
    with open("/srv/files/readme.txt") as f:
        return lang + ":" + f.read()
