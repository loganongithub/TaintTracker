"""Clones each collected repository, scans it, and stores the findings.

Repositories are cloned shallowly (latest commit only) and are only
ever read. Nothing from a clone is executed: no install, no imports,
no tests. A clone is deleted after its scan unless keep=True; the
stored commit hash is enough to fetch the same code again for triage.
"""

import os
import shutil
import stat
import subprocess
from dataclasses import replace
from pathlib import Path

from taintscan.engine import Project
from taintscan.engine.project import python_files
from taintscan.storage import Store

MAX_PYTHON_FILES = 3000  # larger repositories are skipped, not scanned
CLONE_TIMEOUT = 300  # seconds

# Never prompt for a password, and never download large-file-storage content.
GIT_ENV = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"}


class PipelineError(Exception):
    pass


def clone(url: str, destination: Path) -> str:
    """Shallow-clone a repository and return the commit hash that was checked out."""
    remove(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    command = [
        "git", "-c", "core.longpaths=true", "-c", "core.autocrlf=false",
        "clone", "--quiet", "--depth", "1", "--no-tags", "--single-branch",
        url, str(destination),
    ]  # fmt: skip
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, env=GIT_ENV, timeout=CLONE_TIMEOUT
        )
    except subprocess.TimeoutExpired:
        remove(destination)
        raise PipelineError("clone timed out") from None
    if result.returncode != 0:
        # Git can leave a half-checked-out folder behind. Remove it, or a
        # later run would mistake it for a finished clone and scan part of it.
        remove(destination)
        raise PipelineError(f"clone failed: {result.stderr.strip()[:300]}")
    head = subprocess.run(
        ["git", "-C", str(destination), "rev-parse", "HEAD"], capture_output=True, text=True
    )
    return head.stdout.strip()


def remove(path: Path) -> None:
    """Delete a clone. Git marks some files read-only, which Windows refuses to delete."""

    def make_writable(function, target, _error):
        os.chmod(target, stat.S_IWRITE)
        function(target)

    if path.exists():
        shutil.rmtree(path, onexc=make_writable)


def head_commit(repository: Path) -> str | None:
    """The checked-out commit of an existing clone, or None if there is none."""
    if not (repository / ".git").exists():
        return None
    head = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"], capture_output=True, text=True
    )
    return head.stdout.strip() or None


def scan_repo(store: Store, repo, clones: Path, keep: bool = False) -> int:
    """Clone, scan and record one repository. Returns the number of findings.

    A clone kept from an earlier run is scanned as it is, without downloading again.
    """
    name = repo["full_name"]
    destination = clones / name.replace("/", "__")

    def relative(path: str) -> str:
        return Path(path).relative_to(destination).as_posix()

    try:
        commit = head_commit(destination) or clone(repo["url"], destination)
        if len(python_files(destination)) > MAX_PYTHON_FILES:
            raise PipelineError(f"more than {MAX_PYTHON_FILES} Python files")
        project = Project.from_path(destination)
        findings = [
            # Store paths relative to the repository, with forward slashes.
            replace(
                f,
                file=relative(f.file),
                entries=tuple(replace(entry, file=relative(entry.file)) for entry in f.entries),
            )
            for f in project.run()
        ]
        store.save_scan(name, commit, len(project.modules), len(project.skipped), findings)
        return len(findings)
    except (PipelineError, OSError, RecursionError, MemoryError) as error:
        store.save_error(name, f"{type(error).__name__}: {error}")
        return 0
    finally:
        if not keep:
            remove(destination)


def scan_all(store: Store, clones: Path, limit: int | None = None, keep: bool = False) -> None:
    pending = store.repos(status="new", limit=limit)
    for number, repo in enumerate(pending, start=1):
        count = scan_repo(store, repo, clones, keep)
        print(f"[{number}/{len(pending)}] {repo['full_name']}: {count} finding(s)", flush=True)
