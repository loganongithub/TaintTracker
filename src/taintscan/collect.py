"""Finds candidate repositories with the GitHub search API.

Only repository metadata is fetched here. Nothing is cloned.

Set the GITHUB_TOKEN environment variable to raise the rate limit
(10 searches a minute without one, 30 with). The token is only ever
sent to api.github.com.
"""

import json
import os
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator

API = "https://api.github.com/search/repositories"
PAGE_SIZE = 100
MAX_RESULTS = 1000  # GitHub never returns more than this for one query

# GitHub caps one query at 1000 results, so to collect more we sweep across
# star ranges and union the results (the store ignores duplicates). The bands
# are narrow where repositories are dense (few stars) and wide where they are
# sparse (many stars), to stay under 1000 per band.
STAR_BANDS = [
    (5, 6), (7, 8), (9, 10), (11, 13), (14, 17), (18, 22), (23, 29), (30, 39),
    (40, 54), (55, 79), (80, 119), (120, 199), (200, 399), (400, 899), (900, 3000),
]


def _token() -> str | None:
    """A GitHub token: the env var, or the one `gh` is logged in with."""
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        return token
    try:
        result = subprocess.run(
            ["gh", "auth", "token"], capture_output=True, text=True, timeout=10
        )
        return result.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def build_query(
    min_stars: int, max_stars: int, pushed_after: str, max_size_kb: int, keyword: str = "flask"
) -> str:
    """A search for maintained Python repositories that mention the keyword.

    Forks are left out by GitHub's search unless asked for.
    """
    return (
        f"{keyword} language:python archived:false"
        f" stars:{min_stars}..{max_stars} pushed:>={pushed_after} size:<={max_size_kb}"
    )


def parse_repo(item: dict) -> dict:
    """The fields we keep from one search result."""
    return {
        "full_name": item["full_name"],
        "url": item["clone_url"],
        "stars": item.get("stargazers_count", 0),
        "size_kb": item.get("size", 0),
        "pushed_at": item.get("pushed_at"),
        "description": (item.get("description") or "")[:300],
    }


def fetch_page(query: str, page: int, sort: str) -> dict:
    params = urllib.parse.urlencode(
        {"q": query, "sort": sort, "order": "desc", "per_page": PAGE_SIZE, "page": page}
    )
    request = urllib.request.Request(f"{API}?{params}")
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("User-Agent", "taintscan")
    token = _token()
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            if error.code in (403, 429) and attempt < 2:  # rate limited: wait and retry
                time.sleep(int(error.headers.get("Retry-After", 60)))
                continue
            raise
    raise RuntimeError("unreachable")


def search(query: str, limit: int, sort: str = "updated") -> Iterator[dict]:
    """Yield up to `limit` repositories matching the query."""
    found = 0
    for page in range(1, MAX_RESULTS // PAGE_SIZE + 1):
        items = fetch_page(query, page, sort).get("items", [])
        for item in items:
            yield parse_repo(item)
            found += 1
            if found >= limit:
                return
        if len(items) < PAGE_SIZE:
            return
        time.sleep(2)  # stay well under the search rate limit


def sweep(
    pushed_after: str, max_size_kb: int, keyword: str = "flask", min_stars: int = 5
) -> Iterator[dict]:
    """Yield repositories across every star band, widest reach GitHub allows.

    Duplicates between bands are expected (a repo's star count sits in one band,
    so in practice there are few); the caller's store ignores them.
    """
    for low, high in STAR_BANDS:
        if high < min_stars:
            continue
        query = build_query(max(low, min_stars), high, pushed_after, max_size_kb, keyword)
        yield from search(query, MAX_RESULTS, sort="updated")
