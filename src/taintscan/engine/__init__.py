"""The taint engine.

The rest of the project only depends on the three names below.
Nothing in here may import from the plumbing (cli, collect, storage).
"""

from pathlib import Path

from taintscan.engine.project import Project
from taintscan.finding import Finding

__all__ = ["Project", "analyze", "analyze_project"]


def analyze(source: str, filename: str) -> list[Finding]:
    """Findings in one file's source code, treated as a one-file project."""
    project = Project()
    project.add_module(Path(filename).stem, source, filename)
    return project.run()


def analyze_project(root: Path) -> list[Finding]:
    """Findings in every Python file under a directory, analyzed together."""
    return Project.from_path(Path(root)).run()
