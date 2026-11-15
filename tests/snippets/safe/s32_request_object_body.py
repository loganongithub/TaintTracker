# expect: none
import urllib.request

from flask import Flask, abort, request

app = Flask(__name__)


@app.route("/callback")
def callback():
    body = request.args["code"].encode()
    token_request = urllib.request.Request("https://sso.example.com/token", data=body)
    with urllib.request.urlopen(token_request) as reply:
        return reply.read()
