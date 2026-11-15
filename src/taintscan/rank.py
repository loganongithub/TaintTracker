"""Scores findings so the ones most likely to be real bugs come first.

The engine flags when unsure, so most raw findings are not real. The
score does not change what is reported; it only decides the order a
person reads them in. Every adjustment is recorded with its reason so
a score can be explained.

The weights are hand-set starting points. `taintscan benchmark` reports
how well they separate the hand-labelled true and false positives.
"""

import math
import re
from datetime import datetime, timezone

from taintscan.finding import FROM_PATH_PARAM, FROM_URL_PARAM, HIGH, PATH_TRAVERSAL

BASE = 50

# Code that is not part of the running application.
NOT_APP_CODE = re.compile(r"(^|/)(tests?|testing|examples?|samples?|docs?|scripts?|tools)/|(^|/)test_|_test\.py$|(^|/)conftest\.py$")


def score_entry(entry: dict, rule: str) -> tuple[int, list[str]]:
    """Score one way of reaching the sink. Higher is more likely real."""
    points, reasons = 0, []

    def add(amount: int, reason: str) -> None:
        nonlocal points
        points += amount
        reasons.append(f"{amount:+d} {reason}")

    if entry["route"]:
        add(10, "data enters in a Flask view")
    if entry["auth"] == "none" and entry["route"]:
        add(10, "the view has no login decorator")
    elif entry["auth"] == "login":
        add(-5, "the view requires login")
    elif entry["auth"] == "admin":
        add(-15, "the view is admin-only")

    if rule == PATH_TRAVERSAL:
        if entry["source"] == FROM_PATH_PARAM:
            add(10, 'a <path:...> URL parameter can contain "/"')
        elif entry["source"] == FROM_URL_PARAM:
            add(-15, 'a plain URL parameter cannot contain "/"')

    if entry["depth"] == 0:
        add(5, "source and sink are in the same function")
    elif entry["depth"] >= 3:
        add(-5, f"passes through {entry['depth']} calls")

    if entry["guarded"]:
        add(-20, "a validator-looking function is called on the way")
    return points, reasons


def score(finding: dict, repo: dict | None = None, repo_findings: int = 0) -> tuple[int, list[str]]:
    """Score a finding. `finding` has rule, file, confidence and entries;
    `repo` (optional) has stars and pushed_at; `repo_findings` is how many
    high-confidence findings the same repository has."""
    points, reasons = BASE, []

    def add(amount: int, reason: str) -> None:
        nonlocal points
        points += amount
        reasons.append(f"{amount:+d} {reason}")

    if finding["confidence"] != HIGH:
        add(-30, "low confidence: the attacker's control over the value is partial")
    if NOT_APP_CODE.search(finding["file"]):
        add(-30, "the sink is in test, example or tooling code")

    # A sink is as dangerous as its most dangerous entry point.
    entries = finding.get("entries") or []
    if entries:
        best_points, best_reasons = max(
            (score_entry(entry, finding["rule"]) for entry in entries), key=lambda scored: scored[0]
        )
        points += best_points
        reasons += best_reasons
        if len(entries) > 1:
            add(3, f"reachable from {len(entries)} places")

    # Hundreds of findings in one repository are a pattern (often an admin
    # tool where file and network access is the product), not hundreds of bugs.
    if repo_findings > 100:
        add(-25, f"the repository has {repo_findings} findings")
    elif repo_findings > 30:
        add(-15, f"the repository has {repo_findings} findings")

    if repo:
        stars = repo.get("stars") or 0
        if stars:
            add(min(10, round(2 * math.log10(stars + 1) + 1)), f"{stars} stars")
        pushed = repo.get("pushed_at")
        if pushed:
            age = datetime.now(timezone.utc) - datetime.fromisoformat(pushed.replace("Z", "+00:00"))
            if age.days <= 180:
                add(5, "pushed to in the last six months")
    return points, reasons


def auc(labelled: list[tuple[int, bool]]) -> float | None:
    """How well scores separate true from false findings.

    The chance that a randomly chosen true finding outscores a randomly
    chosen false one: 1.0 is perfect, 0.5 is no better than shuffling.
    """
    true = [points for points, is_true in labelled if is_true]
    false = [points for points, is_true in labelled if not is_true]
    if not true or not false:
        return None
    wins = sum((t > f) + 0.5 * (t == f) for t in true for f in false)
    return round(wins / (len(true) * len(false)), 3)
