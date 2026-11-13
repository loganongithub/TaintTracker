# expect: ssrf line 11
import requests as http
from flask import Flask
from flask import request as req

app = Flask(__name__)


@app.route("/fetch")
def fetch():
    return http.get(req.values["url"]).text
