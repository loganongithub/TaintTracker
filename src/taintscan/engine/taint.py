"""What a taint value is.

A taint is a set of labels. Each label is (rule, origin):

- rule: the bug class the value is still dangerous for.
- origin: where the data came from. Either a real source, written with
  a leading "@" ("@request", "@route-path", "@route"), or the name of a
  parameter of the function being analyzed, meaning "this is dangerous
  if the caller passes something dangerous for that parameter".

The parameter labels are what make cross-function tracking work: a
function is analyzed once, without knowing its callers, and the result
is filled in at each call site.

Taint comes in two strengths. Strong taint means the attacker controls
the content of the value. Weak taint (the rule is written with a
leading "~") means their control is partial. Either they only
influenced which value was picked, as in `db.get_book(book_id)` or
`table[key]`, or they control only the end of a URL whose start came
from somewhere else, as in `BASE_URL + user_path`. Weak taint reaching
a sink gives a low-confidence finding.

One extra label, NORMALIZED, is not a bug class. It marks a path that
came straight out of os.path.realpath / abspath / normpath, which is
what makes a later `startswith(base)` check meaningful.
"""

from taintscan.finding import FROM_REQUEST, PATH_TRAVERSAL, SSRF

Label = tuple[str, str | None]
Taint = frozenset[Label]

RULES = (SSRF, PATH_TRAVERSAL)
CLEAN: Taint = frozenset()
NORMALIZED: Label = ("normalized", None)


def from_source(kind: str = FROM_REQUEST) -> Taint:
    """Taint for data read from a real source of the given kind."""
    return frozenset((rule, "@" + kind) for rule in RULES)


def from_param(name: str) -> Taint:
    return frozenset((rule, name) for rule in RULES)


def is_real(origin: str | None) -> bool:
    """True for a real source, False for a parameter placeholder."""
    return origin is None or origin.startswith("@")


def is_weak(rule: str) -> bool:
    return rule.startswith("~")


def base(rule: str) -> str:
    """The bug class of a label's rule, whatever its strength."""
    return rule.lstrip("~")


def weaken(taint: Taint) -> Taint:
    """The same taint, downgraded to "the attacker only chose which value"."""
    return frozenset(("~" + base(rule), origin) for rule, origin in taint if rule != NORMALIZED[0])


def weaken_rule(taint: Taint, rule: str) -> Taint:
    """The same taint with one bug class downgraded to weak."""
    kept = frozenset(label for label in taint if label[0] != rule)
    return kept | weaken(frozenset(label for label in taint if label[0] == rule))


def without(taint: Taint, rule: str) -> Taint:
    """The same taint with one bug class removed (what a sanitizer does)."""
    return frozenset(label for label in taint if base(label[0]) != rule)


def unmarked(taint: Taint) -> Taint:
    """The same taint without the NORMALIZED marker."""
    return taint - {NORMALIZED}
