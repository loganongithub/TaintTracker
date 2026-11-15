# taintscan

Static taint analysis that finds SSRF and path traversal in Flask apps.

Status: phase 4 done. On 9 held-out CVEs the engine detects 7 (78%); on the 8 CVEs its rules were adjusted against it detects all 8. The false-positive rate over the 24 hand-labelled findings is 29%; 81 findings are still unlabelled, and 10 more are low-confidence and not scored. See `benchmarks/RESULTS.md`.

## Known limits

- Python 2 source cannot be parsed and is skipped (the scan reports how many files it skipped).
- Method calls (`obj.method(x)`) are followed when the object's class is visible (assigned from a constructor in the same function or at module level) or when exactly one class in the project defines the method. Constructors (`__init__`) and object fields are not tracked.
- Three kinds of validation check clear a finding: allowlist membership, `re.match`/`fullmatch`, and `startswith` on a resolved path. A check the engine cannot read (a function with a safety-sounding name, a test for `/` or `..`) only lowers the finding to low confidence. Blocklists are not trusted at all.
- Functions defined inside other functions are analyzed but cannot be called across, so validation inside a nested helper is not seen.
- Taint stored in globals, class attributes or databases is not tracked between functions.
- Method calls on objects are not matched as sinks (`requests.Session().get(url)`, `Path(p).read_text()`).

## Setup (Windows)

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
```

## Use

```powershell
.\.venv\Scripts\python -m pytest          # run the snippet suite
.\.venv\Scripts\taintscan scan path\to\code
.\.venv\Scripts\taintscan scan path\to\code --low   # include low-confidence findings
.\.venv\Scripts\taintscan collect --limit 100       # find candidate repos on GitHub
.\.venv\Scripts\taintscan scan-all                  # clone and scan them
.\.venv\Scripts\taintscan status                    # progress so far
.\.venv\Scripts\taintscan top --why                 # stored findings, most likely real first
.\.venv\Scripts\taintscan benchmark       # clone the CVE cases and measure
```

The benchmark clones the repositories listed in `benchmarks/cves.toml` into `benchmarks/checkouts/` and writes `benchmarks/RESULTS.md`. To judge a finding that is not one of the listed CVEs, add a line to `benchmarks/labels.toml` using the key shown in the results, for example `"demo:app.py:12:ssrf" = "fp"` (or `"tp"`).

## Layout

- `src/taintscan/engine/` is the taint engine. Entry points: `analyze(source, filename)` and `analyze_project(directory)`.
  - `taint.py` defines what a taint value is.
  - `tracker.py` walks statements and expressions and tracks taint.
  - `model.py` holds the records for modules, functions and function summaries.
  - `project.py` loads a directory, computes summaries and resolves calls across files.
  - `names.py` resolves imported names (`http.get` to `requests.get`).
  - `routes.py` finds which view-function parameters come from the URL.
- `src/taintscan/rules.py` lists the sources, sinks and sanitizers as data.
- `src/taintscan/finding.py` defines `Finding`, the engine's output type.
- `src/taintscan/cli.py` is the command line.
- `src/taintscan/collect.py` searches GitHub for candidate repositories (metadata only).
- `src/taintscan/pipeline.py` clones each one, scans it and deletes the clone.
- `src/taintscan/rank.py` scores findings so the likeliest real bugs come first, with a reason for every adjustment.
- `src/taintscan/storage.py` keeps repositories and findings in `data/taintscan.db`.
- `src/taintscan/benchmark.py` runs the CVE benchmark; `benchmarks/cves.toml` lists the cases and `benchmarks/SOURCES.md` says where each came from.
- `tests/snippets/` holds small vulnerable and safe files, and `tests/projects/` holds multi-file cases; `tests/test_snippets.py` runs the engine over both.
- `exercises/` holds the phase 1 `ast` exercises.
- `DECISIONS.md` records each design choice and its reason.

Proofs of concept run only against local copies, never a live deployment.
