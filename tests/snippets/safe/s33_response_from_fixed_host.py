# expect: low ssrf line 12
import requests
from flask import Flask, abort, request

app = Flask(__name__)


@app.route("/imagine", methods=["POST"])
def imagine():
    reply = requests.post("https://api.example.com/generate", json={"prompt": request.json["prompt"]})
    image_url = reply.json()["url"]
    return requests.get(image_url).content
