# expect: low path-traversal line 11
from flask import Flask, abort, request

app = Flask(__name__)
PAGES = {"home": "/srv/pages/home.html", "about": "/srv/pages/about.html"}


@app.route("/page")
def page():
    path = PAGES.get(request.args["name"], PAGES["home"])
    with open(path) as f:
        return f.read()
