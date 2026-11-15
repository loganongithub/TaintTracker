# expect: none
import requests
from flask import Flask, abort, request

app = Flask(__name__)
API = "https://api.example.com/v1/"
DRAWS = "https://data.example.com/draws/{year}.json"


@app.route("/item")
def item():
    return requests.get(API + request.args["path"]).text


@app.route("/draws")
def draws():
    return requests.get(DRAWS.format(year=request.args["year"])).text
