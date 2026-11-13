"""Checks the benchmark runner against a throwaway local git repository."""

import subprocess

from taintscan import benchmark

VULNERABLE = """\
from flask import Flask, request

app = Flask(__name__)


@app.route("/read")
def read():
    with open("/srv/files/" + request.args["name"]) as f:
        return f.read()
"""

FIXED = """\
from flask import Flask, request
from werkzeug.utils import secure_filename

app = Flask(__name__)


@app.route("/read")
def read():
    with open("/srv/files/" + secure_filename(request.args["name"])) as f:
        return f.read()
"""

OTHER = """\
import requests
from flask import request


def ping():
    return requests.get(request.args["url"]).text
"""


def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def commit(repo, message):
    git(repo, "add", "-A")
    git(repo, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", message)
    result = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


def test_benchmark_detects_and_clears(tmp_path):
    upstream = tmp_path / "upstream"
    upstream.mkdir()
    git(upstream, "init", "-q")
    (upstream / "app.py").write_text(VULNERABLE, encoding="utf-8")
    (upstream / "other.py").write_text(OTHER, encoding="utf-8")
    commit(upstream, "vulnerable")
    (upstream / "app.py").write_text(FIXED, encoding="utf-8")
    fix = commit(upstream, "fix")

    bench = tmp_path / "bench"
    bench.mkdir()
    (bench / "cves.toml").write_text(
        f"""
[[case]]
id = "demo"
repo = "{upstream.as_posix()}"
fix = "{fix}"

  [[case.cve]]
  id = "CVE-0000-0001"
  rule = "path-traversal"
""",
        encoding="utf-8",
    )
    (bench / "labels.toml").write_text(
        '"demo:other.py:6:ssrf" = "fp"\n"demo:app.py:8:path-traversal" = "tp"\n',
        encoding="utf-8",
    )

    summary = benchmark.run(bench)

    assert summary["cves"] == 1
    assert summary["detected"] == 1
    assert summary["cleared_by_fix"] == 1
    assert summary["other_findings"] == 1
    assert summary["false_positives"] == 1
    assert summary["false_positive_rate"] == 0.5
    assert "CVE-0000-0001" in (bench / "RESULTS.md").read_text(encoding="utf-8")
