# taintscan

Static taint analysis that finds SSRF and path traversal in Flask apps.

Status: phase 4 first run done. The engine detects 8 of 8 benchmark CVEs on a file-level match (see `benchmarks/RESULTS.md`); the false-positive rate is not measured until the other findings are labelled by hand.

## Known limits

- Method calls (`obj.method(x)`) are followed by name only: the engine guesses the method when exactly one class in the project defines it. Ambiguous names, inherited methods and constructors (`__init__`) are not followed.
- A sink reached from several handlers is reported once, naming only one of them.
- Taint stored in globals, class attributes or databases is not tracked between functions.
- Allowlist checks are not recognised as sanitizers, so correctly validated code is still flagged.
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
- `src/taintscan/benchmark.py` runs the CVE benchmark; `benchmarks/cves.toml` lists the cases and `benchmarks/SOURCES.md` says where each came from.
- `tests/snippets/` holds small vulnerable and safe files, and `tests/projects/` holds multi-file cases; `tests/test_snippets.py` runs the engine over both.
- `exercises/` holds the phase 1 `ast` exercises.
- `DECISIONS.md` records each design choice and its reason.

Proofs of concept run only against local copies, never a live deployment.
