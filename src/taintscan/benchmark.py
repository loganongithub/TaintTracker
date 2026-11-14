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
from taintscan.finding import HIGH


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
            "confidence": f.confidence,
        }
        for f in project.run()
    ]
    return {
        "commit": commit,
        "files": len(project.modules),
        "skipped": len(project.skipped),
        # Everything the benchmark scores is high-confidence. Low-confidence
        # findings are kept on the side so they can still be inspected.
        "findings": [f for f in findings if f["confidence"] == HIGH],
        "low_confidence": [f for f in findings if f["confidence"] != HIGH],
    }


def run_case(case: dict, checkouts: Path, labels: dict[str, str]) -> dict:
    repo, vulnerable_commit, fixed_commit, changed = prepare(case, checkouts)
    vulnerable = scan(repo, vulnerable_commit)
    fixed = scan(repo, fixed_commit) if fixed_commit else None

    def matching(scan_result: dict, cve: dict, files: list[str]) -> list[dict]:
        # With no file list at all (no fix commit, none given), any finding
        # of the right bug class in the repository counts: a looser match.
        return [
            f
            for f in scan_result["findings"]
            if f["rule"] == cve["rule"] and (not files or f["file"] in files)
        ]

    for finding in vulnerable["findings"]:
        finding["key"] = f"{case['id']}:{finding['file']}:{finding['line']}:{finding['rule']}"
        finding["label"] = labels.get(finding["key"], "unlabelled")

    def cleared(before: list[dict], after: list[dict]) -> str:
        if not after:
            return "yes"
        return "partly" if len(after) < len(before) else "no"

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
                "match": "file" if files else "repository",
                "detected": bool(hits),
                "hits": hits,
                # Compared by count, because line numbers shift between versions.
                "cleared": None if fixed is None else cleared(hits, matching(fixed, cve, files)),
            }
        )

    others = [finding for finding in vulnerable["findings"] if finding not in explained]

    return {
        "id": case["id"],
        "set": case.get("set", "tuned"),
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
    # The rate uses only findings a person has read and labelled. A finding
    # credited to a CVE by a file match is not assumed to be true.
    everything = [
        f for case in cases if "vulnerable" in case for f in case["vulnerable"]["findings"]
    ]
    true_positives = sum(f["label"] == "tp" for f in everything)
    false_positives = sum(f["label"] == "fp" for f in everything)
    judged = true_positives + false_positives
    by_set: dict[str, dict[str, int]] = {}
    for case in cases:
        counts = by_set.setdefault(case.get("set", "tuned"), {"cves": 0, "detected": 0})
        counts["cves"] += len(case.get("cves", []))
        counts["detected"] += sum(cve["detected"] for cve in case.get("cves", []))
    return {
        "by_set": by_set,
        "cves": len(cves),
        "detected": len(detected),
        "detected_with_fix": len(with_fix),
        "cleared_by_fix": sum(cve["cleared"] == "yes" for cve in with_fix),
        "partly_cleared_by_fix": sum(cve["cleared"] == "partly" for cve in with_fix),
        "findings": len(everything),
        "low_confidence": sum(
            len(case["vulnerable"]["low_confidence"]) for case in cases if "vulnerable" in case
        ),
        "other_findings": len(others),
        "unlabelled": sum(f["label"] == "unlabelled" for f in everything),
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
        *(
            f"  - {name} set: {rate(counts['detected'], counts['cves'])}"
            for name, counts in summary["by_set"].items()
        ),
        f"- Detected CVEs no longer flagged after the fix: "
        f"{rate(summary['cleared_by_fix'], summary['detected_with_fix'])}, "
        f"plus {summary['partly_cleared_by_fix']} with fewer findings than before",
        f"- Findings on vulnerable versions: {summary['findings']}, of which "
        f"{summary['other_findings']} are not credited to a listed CVE",
        f"- Findings not yet labelled by hand: {summary['unlabelled']}",
        f"- Low-confidence findings, not scored: {summary['low_confidence']}",
    ]
    if summary["false_positive_rate"] is None:
        lines.append("- False-positive rate: not measured yet (no findings labelled by hand)")
    else:
        lines.append(
            f"- False-positive rate over hand-labelled findings: "
            f"{summary['false_positive_rate']:.0%} "
            f"({summary['false_positives']} false, {summary['true_positives']} true)"
        )
    lines += [
        "",
        "The tuned set is the cases the engine's rules were adjusted against; the heldout",
        "set was added afterwards and is the fairer number.",
        "",
        "A CVE counts as detected when a finding of the right bug class lands in one of",
        "its files, or anywhere in the repository where the table says so. Either way",
        "each detection still needs a human to confirm it is the same bug.",
        "",
        "| CVE | Repository | Set | Bug class | Detected | Match | Cleared by fix | Where |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for case in cases:
        if "error" in case:
            lines.append(f"| | {case['id']} | {case['set']} | | error | | | {case['error']} |")
            continue
        for cve in case["cves"]:
            cleared = cve["cleared"] or "no fix"
            if not cve["detected"]:
                cleared = "-"  # nothing to clear
            where = ", ".join(f"{h['file']}:{h['line']}" for h in cve["hits"]) or "-"
            detected = "yes" if cve["detected"] else "no"
            lines.append(
                f"| {cve['id']} | {case['id']} | {case['set']} | {cve['rule']} | {detected} "
                f"| {cve['match']} | {cleared} | {where} |"
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
            cases.append(
                {
                    "id": case["id"],
                    "set": case.get("set", "tuned"),
                    "repo": case["repo"],
                    "error": str(error),
                }
            )

    summary = summarize(cases)
    (directory / "results.json").write_text(
        json.dumps({"summary": summary, "cases": cases}, indent=2), encoding="utf-8"
    )
    (directory / "RESULTS.md").write_text(report(cases, summary), encoding="utf-8")
    return summary
