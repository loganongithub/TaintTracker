# expect: none
from flask import Flask

app = Flask(__name__)


@app.route("/shards/<int:index>of<int:total>" +
           "/data")
def shard(index, total):
    with open(f"/srv/shards/{index}_{total}.bin", "rb") as f:
        return f.read()
