# expect: low path-traversal line 15
import sqlite3

from flask import Flask, request

app = Flask(__name__)
db = sqlite3.connect("books.db")


@app.route("/cover")
def cover():
    row = db.execute("SELECT path FROM books WHERE id = ?", (request.args["id"],)).fetchone()
    if row is None:
        return "not found", 404
    with open(row[0], "rb") as f:
        return f.read()
