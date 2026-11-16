"""Checks entry-point recording and the ranking score."""

from taintscan import rank
from taintscan.engine import analyze
from taintscan.finding import FROM_PATH_PARAM, FROM_REQUEST, FROM_URL_PARAM

TWO_HANDLERS = """\
from flask import Flask, request
from flask_login import login_required

app = Flask(__name__)


def read(path):
    with open(path) as f:
        return f.read()


@app.route("/public/<path:name>")
def public(name):
    return read("/srv/files/" + name)


@app.route("/private")
@login_required
def private():
    return read("/srv/files/" + request.args["name"])
"""


def entry(**changes):
    base = {
        "function": "app.view", "file": "app.py", "line": 10, "source": FROM_REQUEST,
        "depth": 0, "route": True, "auth": "none", "guarded": False,
    }  # fmt: skip
    return {**base, **changes}


def finding(**changes):
    base = {"rule": "path-traversal", "file": "app.py", "confidence": "high", "entries": [entry()]}
    return {**base, **changes}


def test_every_entry_point_is_recorded():
    (found,) = analyze(TWO_HANDLERS, "app.py")
    assert found.line == 8
    by_function = {e.function: e for e in found.entries}
    assert set(by_function) == {"app.public", "app.private"}

    public, private = by_function["app.public"], by_function["app.private"]
    assert (public.source, public.auth, public.route, public.depth) == (
        FROM_PATH_PARAM, "none", True, 1,
    )  # fmt: skip
    assert (private.source, private.auth, private.line) == (FROM_REQUEST, "login", 20)


def test_validator_looking_call_marks_the_entry_guarded():
    source = TWO_HANDLERS.replace(
        'return read("/srv/files/" + name)',
        'validate_name(name)\n    return read("/srv/files/" + name)',
    )
    (found,) = analyze(source, "app.py")
    guarded = {e.function: e.guarded for e in found.entries}
    assert guarded == {"app.public": True, "app.private": False}


def test_signals_move_the_score_the_right_way():
    plain, _ = rank.score(finding())
    assert rank.score(finding(confidence="low"))[0] < plain
    assert rank.score(finding(file="tests/test_app.py"))[0] < plain
    assert rank.score(finding(entries=[entry(auth="admin")]))[0] < plain
    assert rank.score(finding(entries=[entry(guarded=True)]))[0] < plain
    assert rank.score(finding(entries=[entry(source=FROM_URL_PARAM)]))[0] < plain
    assert rank.score(finding(entries=[entry(source=FROM_PATH_PARAM)]))[0] > plain
    assert rank.score(finding(), repo_findings=200)[0] < plain


def test_a_finding_is_scored_by_its_most_dangerous_entry():
    admin_only = finding(entries=[entry(auth="admin")])
    also_public = finding(entries=[entry(auth="admin"), entry(function="app.open_view")])
    assert rank.score(also_public)[0] > rank.score(admin_only)[0]


def test_every_adjustment_comes_with_a_reason():
    points, reasons = rank.score(finding(entries=[entry(guarded=True)]))
    total = sum(int(reason.split()[0]) for reason in reasons)
    assert points == rank.BASE + total


def test_auc():
    assert rank.auc([(90, True), (80, True), (40, False)]) == 1.0
    assert rank.auc([(10, True), (40, False)]) == 0.0
    assert rank.auc([(50, True), (50, False)]) == 0.5
    assert rank.auc([(50, True)]) is None


HOOKED = """\
from flask import Flask, abort, request, session

app = Flask(__name__)


@app.before_request
def require_login():
    if not session.get("user"):
        abort(401)


@app.route("/read")
def read():
    with open("/srv/files/" + request.args["name"]) as f:
        return f.read()
"""


def test_a_before_request_hook_is_noted_and_removes_the_no_login_bonus():
    (found,) = analyze(HOOKED, "app.py")
    assert found.entries[0].auth == "hook"
    (bare,) = analyze(HOOKED.replace("@app.before_request\n", ""), "app.py")
    assert bare.entries[0].auth == "none"
    as_dict = lambda f: {"rule": f.rule, "file": f.file, "confidence": f.confidence,
                         "entries": [vars(e) for e in f.entries]}  # noqa: E731
    assert rank.score(as_dict(found))[0] < rank.score(as_dict(bare))[0]


SHAPED_LIKE_A_VALIDATOR = """\
import os

from flask import Flask, request

app = Flask(__name__)


def pruefen(ziel):
    ziel = os.path.realpath(ziel)
    if os.path.commonpath([ziel, "/srv"]) != "/srv":
        raise ValueError("nicht erlaubt")
    return ziel


@app.route("/read")
def read():
    with open(pruefen(request.args["ziel"])) as f:
        return f.read()
"""


def test_a_function_shaped_like_a_validator_marks_the_entry_guarded():
    findings = analyze(SHAPED_LIKE_A_VALIDATOR, "app.py")
    assert findings and all(entry.guarded for f in findings for entry in f.entries)
