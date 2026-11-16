# expect: low path-traversal line 20
from flask import Flask, abort, request

app = Flask(__name__)
JOBS = {}


class JobStore:
    @staticmethod
    def get_by_id(job_id):
        return JOBS.get(job_id)


@app.route("/attach", methods=["POST"])
def attach():
    job_id = request.form["job_id"]
    job = JobStore.get_by_id(job_id)
    if job is None:
        return "unknown job", 404
    with open("/srv/jobs/" + job_id + "/manifest.json") as f:
        return f.read()
