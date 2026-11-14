"""Command line entry point.

taintscan scan <file-or-directory>
taintscan benchmark [directory]
"""

import argparse
import sys
from pathlib import Path

from taintscan.engine import Project
from taintscan.finding import HIGH


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="taintscan")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="scan a file or directory")
    scan.add_argument("path", type=Path)
    scan.add_argument("--low", action="store_true", help="also show low-confidence findings")
    bench = commands.add_parser("benchmark", help="measure against known CVEs")
    bench.add_argument("directory", type=Path, nargs="?", default=Path("benchmarks"))
    args = parser.parse_args(argv)

    if args.command == "benchmark":
        from taintscan import benchmark

        summary = benchmark.run(args.directory)
        print(f"detected {summary['detected']} of {summary['cves']} CVEs")
        print(f"results written to {args.directory / 'RESULTS.md'}")
        return 0

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
    print(f"{len(high)} finding(s) in {len(project.modules)} file(s)")
    if low and not args.low:
        print(f"{len(low)} low-confidence finding(s) hidden; add --low to show them")
    return 1 if high else 0


if __name__ == "__main__":
    sys.exit(main())
