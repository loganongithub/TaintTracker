"""Runs the engine over the test snippets and projects and checks the result.

Every test file declares what the engine should report in it on its first line:

    # expect: ssrf line 10
    # expect: path-traversal line 8, path-traversal line 13
    # expect: none

tests/snippets/ holds single files, each analyzed alone.
tests/projects/ holds directories, each analyzed as one multi-file project.
"""

import re
from pathlib import Path

import pytest

from taintscan.engine import analyze, analyze_project

HERE = Path(__file__).parent
SNIPPETS = sorted((HERE / "snippets").rglob("*.py"))
PROJECTS = sorted(p for p in (HERE / "projects").iterdir() if p.is_dir())

EXPECT_LINE = re.compile(r"#\s*expect:\s*(.+)$")
EXPECT_ITEM = re.compile(r"([\w-]+) line (\d+)$")


def expected_findings(path: Path) -> set[tuple[str, int]]:
    first_line = path.read_text(encoding="utf-8").splitlines()[0]
    match = EXPECT_LINE.match(first_line)
    if not match:
        raise ValueError(f"{path}: first line must be an '# expect:' comment")
    if match[1].strip() == "none":
        return set()
    items = [EXPECT_ITEM.match(item.strip()) for item in match[1].split(",")]
    if not all(items):
        raise ValueError(f"{path}: cannot read '{first_line}'")
    return {(item[1], int(item[2])) for item in items}


@pytest.mark.parametrize("path", SNIPPETS, ids=lambda p: p.stem)
def test_snippet(path):
    findings = analyze(path.read_text(encoding="utf-8"), str(path))
    assert {(f.rule, f.line) for f in findings} == expected_findings(path)


@pytest.mark.parametrize("root", PROJECTS, ids=lambda p: p.name)
def test_project(root):
    findings = analyze_project(root)
    for path in sorted(root.rglob("*.py")):
        got = {(f.rule, f.line) for f in findings if Path(f.file) == path}
        assert got == expected_findings(path), path.relative_to(root)
