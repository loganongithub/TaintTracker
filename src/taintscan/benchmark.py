"""Measures the scanner against known CVEs listed in benchmarks/cves.toml.

For each repository it checks out the vulnerable version and (if there
is one) the fixed version, scans both, and records:

- detected: the vulnerable version has a finding of the right bug class
  in one of the CVE's files.
- cleared: the fixed version no longer has such a finding.
- other findings: everything else reported on the vulnerable version.
  These are unknown until labelled by hand in benchmarks/labels.toml.

Code is only ever cloned and read. Nothing from a checkout is executed.
"""

import json
import subprocess
import tomllib
from pathlib import Path

from taintscan.engine import Project


class BenchmarkError(Exception):
    pass


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, encoding="utf-8"
    )
    if result.returncode != 0:
        raise BenchmarkError(f"git {' '.join(args)}: {result.stderr.strip()}")
    return result.stdout.strip()


def has_commit(repo: Path, ref: str) -> bool:
    result = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "-e", f"{ref}^{{commit}}"], capture_output=True
    )
    return result.returncode == 0


def fetch(repo: Path, ref: str, depth: int) -> str:
    """Make a commit (and depth-1 ancestors) available locally; return its hash."""
    if not (has_commit(repo, ref) and (depth == 1 or has_commit(repo, f"{ref}~{depth - 1}"))):
        git(repo, "fetch", "--quiet", "--depth", str(depth), "origin", ref)
        ref = "FETCH_HEAD"
    return git(repo, "rev-parse", f"{ref}^{{commit}}")


def prepare(case: dict, checkouts: Path) -> tuple[Path, str, str | None, list[str]]:
    """Clone if needed. Returns (repo, vulnerable commit, fixed commit, files the fix changed)."""
    repo = checkouts / case["id"]
    if not (repo / ".git").exists():
        repo.mkdir(parents=True, exist_ok=True)
        git(repo, "init", "--quiet")
        git(repo, "config", "core.autocrlf", "false")
        git(repo, "config", "core.longpaths", "true")
        git(repo, "remote", "add", "origin", case["repo"])

    changed: list[str] = []
    fix = case.get("fix")
    if fix:
        fix = fetch(repo, fix, depth=2)
        changed = git(repo, "diff", "--name-only", f"{fix}~1", fix).splitlines()

    if "vulnerable" in case:
        vulnerable = fetch(repo, case["vulnerable"], depth=1)
    elif fix:
        vulnerable = git(repo, "rev-parse", f"{fix}~1")
    else:
        raise BenchmarkError(f"{case['id']}: needs 'fix' or 'vulnerable'")

    fixed = fetch(repo, case["fixed"], depth=1) if "fixed" in case else fix
    return repo, vulnerable, fixed, [f for f in changed if f.endswith(".py")]


def scan(repo: Path, commit: str) -> dict:
    git(repo, "checkout", "--quiet", "--detach", "--force", commit)
    project = Project.from_path(repo)
    findings = [
        {
            "rule": f.rule,
            "file": Path(f.file).relative_to(repo).as_posix(),
            "line": f.line,
            "message": f.message.replace(str(repo), "").replace("\\", "/"),
        }
        for f in project.run()
    ]
    return {
        "commit": commit,
        "files": len(project.modules),
        "skipped": len(project.skipped),
        "findings": findings,
    }


def run_case(case: dict, checkouts: Path, labels: dict[str, str]) -> dict:
    repo, vulnerable_commit, fixed_commit, changed = prepare(case, checkouts)
    vulnerable = scan(repo, vulnerable_commit)
    fixed = scan(repo, fixed_commit) if fixed_commit else None

    def matching(scan_result: dict, cve: dict, files: list[str]) -> list[dict]:
        return [
            f for f in scan_result["findings"] if f["rule"] == cve["rule"] and f["file"] in files
        ]

    cves, explained = [], []
    for cve in case["cve"]:
        files = cve.get("files") or changed
        hits = matching(vulnerable, cve, files)
        explained += hits
        cves.append(
            {
                "id": cve["id"],
                "rule": cve["rule"],
                "files": files,
                "detected": bool(hits),
                "hits": hits,
                "cleared": None if fixed is None else not matching(fixed, cve, files),
            }
        )

    others = []
    for finding in vulnerable["findings"]:
        if finding not in explained:
            key = f"{case['id']}:{finding['file']}:{finding['line']}:{finding['rule']}"
            others.append({**finding, "key": key, "label": labels.get(key, "unlabelled")})

    return {
        "id": case["id"],
        "repo": case["repo"],
        "vulnerable": vulnerable,
        "fixed": fixed,
        "cves": cves,
        "other_findings": others,
    }


def summarize(cases: list[dict]) -> dict:
    cves = [cve for case in cases for cve in case.get("cves", [])]
    detected = [cve for cve in cves if cve["detected"]]
    with_fix = [cve for cve in detected if cve["cleared"] is not None]
    others = [f for case in cases for f in case.get("other_findings", [])]
    true_positives = sum(len(cve["hits"]) for cve in detected)
    true_positives += sum(f["label"] == "tp" for f in others)
    false_positives = sum(f["label"] == "fp" for f in others)
    # No rate until someone has labelled at least one finding by hand:
    # CVE matches alone would always give a flattering 0%.
    labelled = sum(f["label"] in ("tp", "fp") for f in others)
    judged = true_positives + false_positives if labelled else 0
    return {
        "cves": len(cves),
        "detected": len(detected),
        "detected_with_fix": len(with_fix),
        "cleared_by_fix": sum(cve["cleared"] for cve in with_fix),
        "other_findings": len(others),
        "unlabelled": sum(f["label"] == "unlabelled" for f in others),
        "true_positives": true_positives,
        "false_positives": false_positives,
        # Only over findings someone has judged; unlabelled ones are left out.
        "false_positive_rate": round(false_positives / judged, 3) if judged else None,
    }


def report(cases: list[dict], summary: dict) -> str:
    def rate(part: int, whole: int) -> str:
        return f"{part}/{whole}" + (f" ({part / whole:.0%})" if whole else "")

    lines = [
        "# Benchmark results",
        "",
        "Generated by `taintscan benchmark`. Do not edit by hand.",
        "",
        f"- CVEs detected: {rate(summary['detected'], summary['cves'])}",
        f"- Detected CVEs no longer flagged after the fix: "
        f"{rate(summary['cleared_by_fix'], summary['detected_with_fix'])}",
        f"- Other findings on vulnerable versions: {summary['other_findings']} "
        f"({summary['unlabelled']} not yet labelled)",
    ]
    if summary["false_positive_rate"] is None:
        lines.append("- False-positive rate: not measured yet (no findings labelled by hand)")
    else:
        lines.append(
            f"- False-positive rate over judged findings: {summary['false_positive_rate']:.0%} "
            f"({summary['false_positives']} false, {summary['true_positives']} true)"
        )
    lines += [
        "",
        "A CVE counts as detected when a finding of the right bug class lands in one of",
        "its files. That is a file-level match, so each detection still needs a human to",
        "confirm it is the same bug.",
        "",
        "| CVE | Repository | Bug class | Detected | Cleared by fix | Where |",
        "|---|---|---|---|---|---|",
    ]
    for case in cases:
        if "error" in case:
            lines.append(f"| | {case['id']} | | error | | {case['error']} |")
            continue
        for cve in case["cves"]:
            cleared = {None: "no fix", True: "yes", False: "no"}[cve["cleared"]]
            if not cve["detected"]:
                cleared = "-"  # nothing to clear
            where = ", ".join(f"{h['file']}:{h['line']}" for h in cve["hits"]) or "-"
            detected = "yes" if cve["detected"] else "no"
            lines.append(
                f"| {cve['id']} | {case['id']} | {cve['rule']} | {detected} | {cleared} | {where} |"
            )
    lines += ["", "## Other findings", ""]
    for case in cases:
        for f in case.get("other_findings", []):
            lines.append(f"- `{f['key']}` ({f['label']}): {f['message']}")
    if lines[-1] == "":
        lines.append("None.")
    return "\n".join(lines) + "\n"


def run(directory: Path) -> dict:
    """Run every case in <directory>/cves.toml and write results next to it."""
    manifest = tomllib.loads((directory / "cves.toml").read_text(encoding="utf-8"))
    labels_file = directory / "labels.toml"
    labels = tomllib.loads(labels_file.read_text(encoding="utf-8")) if labels_file.exists() else {}

    cases = []
    for case in manifest["case"]:
        print(f"{case['id']} ...", flush=True)
        try:
            cases.append(run_case(case, directory / "checkouts", labels))
        except BenchmarkError as error:
            cases.append({"id": case["id"], "repo": case["repo"], "error": str(error)})

    summary = summarize(cases)
    (directory / "results.json").write_text(
        json.dumps({"summary": summary, "cases": cases}, indent=2), encoding="utf-8"
    )
    (directory / "RESULTS.md").write_text(report(cases, summary), encoding="utf-8")
    return summary
