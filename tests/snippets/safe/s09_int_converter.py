# expect: none
from flask import Flask

app = Flask(__name__)


@app.route("/items/<int:item_id>")
def item(item_id):
    with open(f"/srv/items/{item_id}.json") as f:
        return f.read()
