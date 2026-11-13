"""Command line entry point.

taintscan scan <file-or-directory>
taintscan benchmark [directory]
"""

import argparse
import sys
from pathlib import Path

from taintscan.engine import Project


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="taintscan")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="scan a file or directory")
    scan.add_argument("path", type=Path)
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
    for finding in findings:
        print(f"{finding.file}:{finding.line}: {finding.rule}: {finding.message}")
    print(f"{len(findings)} finding(s) in {len(project.modules)} file(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
