# expect: ssrf line 12
import urllib.request

from flask import Flask, abort, request

app = Flask(__name__)


@app.route("/fetch")
def fetch():
    page_request = urllib.request.Request(request.args["url"], headers={"Accept": "text/html"})
    with urllib.request.urlopen(page_request) as reply:
        return reply.read()
