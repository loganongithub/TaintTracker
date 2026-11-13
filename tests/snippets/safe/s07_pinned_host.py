# expect: none
import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def user():
    name = request.args.get("user")
    return requests.get("https://api.example.com/users/" + name).text
