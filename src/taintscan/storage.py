"""SQLite storage for collected repositories and their findings.

Two tables:
  repos     one row per GitHub repository, with its scan status
  findings  one row per finding, linked to a repo
"""

import json
import sqlite3
from contextlib import closing
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from taintscan.finding import Finding

SCHEMA = """
CREATE TABLE IF NOT EXISTS repos (
    full_name   TEXT PRIMARY KEY,          -- owner/name
    url         TEXT NOT NULL,             -- clone URL
    stars       INTEGER NOT NULL DEFAULT 0,
    size_kb     INTEGER NOT NULL DEFAULT 0,
    pushed_at   TEXT,                      -- last push, ISO date
    description TEXT,
    status      TEXT NOT NULL DEFAULT 'new',  -- new | scanned | error
    commit_sha  TEXT,                      -- the commit that was scanned
    files       INTEGER,                   -- Python files analyzed
    skipped     INTEGER,                   -- Python files that could not be parsed
    scanned_at  TEXT,
    error       TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id         INTEGER PRIMARY KEY,
    repo       TEXT NOT NULL REFERENCES repos(full_name),
    rule       TEXT NOT NULL,
    file       TEXT NOT NULL,              -- path inside the repository
    line       INTEGER NOT NULL,
    message    TEXT NOT NULL,
    confidence TEXT NOT NULL,
    entries    TEXT NOT NULL DEFAULT '[]', -- JSON list of entry points (see finding.Entry)
    UNIQUE (repo, rule, file, line)
);
"""


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        columns = [row["name"] for row in self.db.execute("PRAGMA table_info(findings)")]
        if "entries" not in columns:  # a database made before entry points were stored
            self.db.execute("ALTER TABLE findings ADD COLUMN entries TEXT NOT NULL DEFAULT '[]'")

    def close(self) -> None:
        self.db.close()

    def add_repo(self, repo: dict) -> bool:
        """Insert a repository if it is new. Returns True if it was added."""
        with self.db:
            cursor = self.db.execute(
                "INSERT OR IGNORE INTO repos (full_name, url, stars, size_kb, pushed_at, description)"
                " VALUES (:full_name, :url, :stars, :size_kb, :pushed_at, :description)",
                repo,
            )
        return cursor.rowcount == 1

    def repos(self, status: str | None = None, limit: int | None = None) -> list[sqlite3.Row]:
        query, args = "SELECT * FROM repos", []
        if status:
            query += " WHERE status = ?"
            args.append(status)
        query += " ORDER BY full_name"
        if limit:
            query += " LIMIT ?"
            args.append(limit)
        with closing(self.db.execute(query, args)) as cursor:
            return cursor.fetchall()

    def save_scan(
        self, full_name: str, commit: str, files: int, skipped: int, findings: list[Finding]
    ) -> None:
        """Record a finished scan, replacing any earlier findings for the repo."""
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self.db:
            self.db.execute("DELETE FROM findings WHERE repo = ?", (full_name,))
            self.db.executemany(
                "INSERT OR IGNORE INTO findings"
                " (repo, rule, file, line, message, confidence, entries)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        full_name, f.rule, f.file, f.line, f.message, f.confidence,
                        json.dumps([asdict(entry) for entry in f.entries]),
                    )  # fmt: skip
                    for f in findings
                ],
            )
            self.db.execute(
                "UPDATE repos SET status = 'scanned', commit_sha = ?, files = ?, skipped = ?,"
                " scanned_at = ?, error = NULL WHERE full_name = ?",
                (commit, files, skipped, now, full_name),
            )

    def save_error(self, full_name: str, error: str) -> None:
        with self.db:
            self.db.execute(
                "UPDATE repos SET status = 'error', error = ? WHERE full_name = ?",
                (error[:500], full_name),
            )

    def findings(self, confidence: str | None = None) -> list[sqlite3.Row]:
        """Findings joined with their repository's details."""
        query = (
            "SELECT f.*, r.stars, r.pushed_at, r.commit_sha, r.url FROM findings f"
            " JOIN repos r ON r.full_name = f.repo"
        )
        args = []
        if confidence:
            query += " WHERE f.confidence = ?"
            args.append(confidence)
        query += " ORDER BY f.repo, f.file, f.line"
        with closing(self.db.execute(query, args)) as cursor:
            return cursor.fetchall()

    def reset(self) -> None:
        """Mark every repository as not yet scanned, so scan-all does them again."""
        with self.db:
            self.db.execute("UPDATE repos SET status = 'new', error = NULL")

    def counts(self) -> dict[str, int]:
        with closing(self.db.execute("SELECT status, COUNT(*) FROM repos GROUP BY status")) as c:
            counts = dict(c.fetchall())
        with closing(self.db.execute("SELECT COUNT(*) FROM findings")) as c:
            counts["findings"] = c.fetchone()[0]
        return counts
