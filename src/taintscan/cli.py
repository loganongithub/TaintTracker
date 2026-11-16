"""Command line entry point.

taintscan scan <file-or-directory>      scan local code
taintscan benchmark [directory]         measure against known CVEs
taintscan collect                       find candidate repositories on GitHub
taintscan scan-all                      clone and scan the collected repositories
taintscan status                        show how far collection and scanning have got
taintscan top                           show the stored findings, most likely real first
"""

import argparse
import json
import sys
import tomllib
from datetime import date, timedelta
from pathlib import Path

from taintscan.engine import Project
from taintscan.finding import HIGH

DATA = Path("data")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="taintscan")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="scan a file or directory")
    scan.add_argument("path", type=Path)
    scan.add_argument("--low", action="store_true", help="also show low-confidence findings")

    bench = commands.add_parser("benchmark", help="measure against known CVEs")
    bench.add_argument("directory", type=Path, nargs="?", default=Path("benchmarks"))

    two_years_ago = (date.today() - timedelta(days=730)).isoformat()
    collect = commands.add_parser("collect", help="find candidate repositories on GitHub")
    collect.add_argument("--limit", type=int, default=100, help="how many to add (default 100)")
    collect.add_argument("--min-stars", type=int, default=20)
    collect.add_argument("--max-stars", type=int, default=3000)
    collect.add_argument("--pushed-after", default=two_years_ago, help="YYYY-MM-DD")
    collect.add_argument("--max-size-mb", type=int, default=50)
    collect.add_argument("--dry-run", action="store_true", help="list matches without saving")

    scan_all = commands.add_parser("scan-all", help="clone and scan collected repositories")
    scan_all.add_argument("--limit", type=int, help="stop after this many repositories")
    scan_all.add_argument("--keep", action="store_true", help="keep the clones after scanning")
    scan_all.add_argument("--rescan", action="store_true", help="scan every repository again")

    top = commands.add_parser("top", help="show stored findings, most likely real first")
    top.add_argument("--limit", type=int, default=20)
    top.add_argument("--per-repo", type=int, default=3, help="most findings shown per repository")
    top.add_argument("--rule", choices=["ssrf", "path-traversal"])
    top.add_argument("--why", action="store_true", help="show how each score was reached")

    commands.add_parser("status", help="show collection and scan progress")

    for command in (collect, scan_all, top, commands.choices["status"]):
        command.add_argument("--data", type=Path, default=DATA, help="data directory")
    return parser


def run_scan(args) -> int:
    if not args.path.exists():
        print(f"no such path: {args.path}", file=sys.stderr)
        return 2

    project = Project.from_path(args.path)
    findings = project.run()

    for file, reason in project.skipped:
        print(f"skipped {file}: {reason}", file=sys.stderr)
    high = [f for f in findings if f.confidence == HIGH]
    low = [f for f in findings if f.confidence != HIGH]
    for finding in high + (low if args.low else []):
        tag = "" if finding.confidence == HIGH else " [low confidence]"
        print(f"{finding.file}:{finding.line}: {finding.rule}{tag}: {finding.message}")
        for entry in finding.entries:
            if (entry.file, entry.line) != (finding.file, finding.line):
                print(f"    from {entry.function} ({entry.file}:{entry.line})")
    print(f"{len(high)} finding(s) in {len(project.modules)} file(s)")
    if low and not args.low:
        print(f"{len(low)} low-confidence finding(s) hidden; add --low to show them")
    return 1 if high else 0


def run_benchmark(args) -> int:
    from taintscan import benchmark

    summary = benchmark.run(args.directory)
    print(f"detected {summary['detected']} of {summary['cves']} CVEs")
    print(f"results written to {args.directory / 'RESULTS.md'}")
    return 0


def run_collect(args) -> int:
    from taintscan import collect
    from taintscan.storage import Store

    query = collect.build_query(
        args.min_stars, args.max_stars, args.pushed_after, args.max_size_mb * 1000
    )
    print(f"query: {query}")
    store = None if args.dry_run else Store(args.data / "taintscan.db")
    added = total_kb = 0
    # Ask for extra results, because some will already be in the database.
    for repo in collect.search(query, limit=args.limit * 3):
        if store is None or store.add_repo(repo):
            added += 1
            total_kb += repo["size_kb"]
            if args.dry_run:
                print(f"  {repo['full_name']}  {repo['stars']} stars  {repo['size_kb']} KB")
        if added >= args.limit:
            break
    verb = "matched" if args.dry_run else "added"
    print(f"{verb} {added} repositories, {total_kb / 1000:.0f} MB in total on GitHub")
    return 0


def run_scan_all(args) -> int:
    from taintscan import pipeline
    from taintscan.storage import Store

    store = Store(args.data / "taintscan.db")
    if args.rescan:
        store.reset()
    pipeline.scan_all(store, args.data / "clones", args.limit, args.keep)
    print(store.counts())
    return 0


def run_status(args) -> int:
    from taintscan.storage import Store

    store = Store(args.data / "taintscan.db")
    for key, value in sorted(store.counts().items()):
        print(f"{key}: {value}")
    return 0


def ranked_findings(store) -> list[dict]:
    """Every stored finding with its score and reasons, best first."""
    from taintscan import rank

    rows = [dict(row) for row in store.findings()]
    per_repo: dict[str, int] = {}
    for row in rows:
        if row["confidence"] == HIGH:
            per_repo[row["repo"]] = per_repo.get(row["repo"], 0) + 1
    for row in rows:
        row["entries"] = json.loads(row["entries"])
        row["score"], row["reasons"] = rank.score(row, row, per_repo.get(row["repo"], 0))
    return sorted(rows, key=lambda row: (-row["score"], row["repo"], row["file"], row["line"]))


def load_verdicts(data: Path) -> dict[str, str]:
    """Triage verdicts from <data>/labels.toml: "repo:file:line:rule" -> verdict.

    The file is private (the data directory is git-ignored): it names
    possible vulnerabilities in other people's projects.
    """
    labels = data / "labels.toml"
    return tomllib.loads(labels.read_text(encoding="utf-8")) if labels.exists() else {}


def run_top(args) -> int:
    from taintscan.storage import Store

    store = Store(args.data / "taintscan.db")
    verdicts = load_verdicts(args.data)
    tally: dict[str, int] = {}
    shown: dict[str, int] = {}
    printed = 0
    for row in ranked_findings(store):
        if args.rule and row["rule"] != args.rule:
            continue
        if shown.get(row["repo"], 0) >= args.per_repo:
            continue  # do not let one repository fill the list
        shown[row["repo"]] = shown.get(row["repo"], 0) + 1
        printed += 1
        verdict = verdicts.get(f"{row['repo']}:{row['file']}:{row['line']}:{row['rule']}", "not triaged")
        tally[verdict] = tally.get(verdict, 0) + 1
        print(f"{printed:>3}. [{row['score']}] {row['repo']}  {row['rule']}  ({verdict})")
        print(f"     {row['file']}:{row['line']}  {row['message']}")
        for entry in row["entries"][:3]:
            print(
                f"     from {entry['function']} ({entry['file']}:{entry['line']})"
                f"  source={entry['source']} auth={entry['auth']}"
            )
        if args.why:
            for reason in row["reasons"]:
                print(f"       {reason}")
        if printed >= args.limit:
            break
    if not printed:
        print("no findings stored yet; run `taintscan collect` and `taintscan scan-all` first")
    elif verdicts:
        order = ["real", "plausible", "unsure", "fp", "not triaged"]
        parts = [f"{tally[v]} {v}" for v in order if tally.get(v)]
        print(f"\nof the {printed} shown: " + ", ".join(parts))
    return 0


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {
        "scan": run_scan,
        "benchmark": run_benchmark,
        "collect": run_collect,
        "scan-all": run_scan_all,
        "status": run_status,
        "top": run_top,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
