"""Checks collection parsing, storage, and the clone-scan-store pipeline.

Nothing here touches the network: the "remote" is a throwaway local git repository.
"""

import subprocess

from taintscan import collect, pipeline
from taintscan.storage import Store

APP = """\
import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/fetch")
def fetch():
    return requests.get(request.args["url"]).text
"""


def make_repo(path, files):
    path.mkdir()

    def git(*args):
        subprocess.run(["git", "-C", str(path), *args], check=True, capture_output=True)

    git("init", "-q")
    for name, content in files.items():
        (path / name).write_text(content, encoding="utf-8")
    git("add", "-A")
    git("-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "init")


def repo_row(name, url):
    return {
        "full_name": name,
        "url": url,
        "stars": 42,
        "size_kb": 10,
        "pushed_at": "2026-01-01T00:00:00Z",
        "description": "demo",
    }


def test_parse_repo_keeps_the_fields_we_store():
    item = {
        "full_name": "someone/app",
        "clone_url": "https://github.com/someone/app.git",
        "stargazers_count": 120,
        "size": 345,
        "pushed_at": "2026-05-01T10:00:00Z",
        "description": None,
        "ignored": "field",
    }
    assert collect.parse_repo(item) == {
        "full_name": "someone/app",
        "url": "https://github.com/someone/app.git",
        "stars": 120,
        "size_kb": 345,
        "pushed_at": "2026-05-01T10:00:00Z",
        "description": "",
    }


def test_build_query_has_every_filter():
    query = collect.build_query(20, 3000, "2024-11-14", 50000)
    for part in ("flask", "language:python", "stars:20..3000", "pushed:>=2024-11-14", "size:<=50000"):
        assert part in query


def test_store_ignores_a_repo_it_already_has(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    assert store.add_repo(repo_row("a/b", "url")) is True
    assert store.add_repo(repo_row("a/b", "url")) is False
    assert len(store.repos()) == 1
    store.close()


def test_scan_all_clones_scans_and_records(tmp_path):
    make_repo(tmp_path / "vulnerable", {"app.py": APP})
    make_repo(tmp_path / "clean", {"app.py": "print('hello')\n"})
    store = Store(tmp_path / "data" / "db.sqlite")
    store.add_repo(repo_row("demo/vulnerable", (tmp_path / "vulnerable").as_posix()))
    store.add_repo(repo_row("demo/clean", (tmp_path / "clean").as_posix()))
    store.add_repo(repo_row("demo/missing", (tmp_path / "does-not-exist").as_posix()))

    pipeline.scan_all(store, tmp_path / "data" / "clones")

    status = {row["full_name"]: row["status"] for row in store.repos()}
    assert status == {
        "demo/vulnerable": "scanned",
        "demo/clean": "scanned",
        "demo/missing": "error",
    }
    findings = store.findings()
    assert [(f["repo"], f["rule"], f["file"], f["line"]) for f in findings] == [
        ("demo/vulnerable", "ssrf", "app.py", 9)
    ]
    assert len(findings[0]["commit_sha"]) == 40
    assert not any((tmp_path / "data" / "clones").iterdir())  # clones are removed afterwards
    store.close()
