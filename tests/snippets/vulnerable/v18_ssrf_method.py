# expect: ssrf line 10
import requests
from flask import Flask, request

app = Flask(__name__)


class Fetcher:
    def send(self, base_url, timeout=5):
        return requests.get(base_url, timeout=timeout)


fetcher = Fetcher()


@app.route("/fetch")
def fetch():
    return fetcher.send(base_url=request.args.get("url")).text
