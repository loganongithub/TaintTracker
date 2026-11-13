"""What a taint value is.

A taint is a set of labels. Each label is (rule, origin):

- rule: the bug class the value is still dangerous for.
- origin: None if the data really came from a source, or the name of a
  parameter of the function being analyzed, meaning "this is dangerous
  if the caller passes something dangerous for that parameter".

The parameter labels are what make cross-function tracking work: a
function is analyzed once, without knowing its callers, and the result
is filled in at each call site.
"""

from taintscan.finding import PATH_TRAVERSAL, SSRF

Label = tuple[str, str | None]
Taint = frozenset[Label]

RULES = (SSRF, PATH_TRAVERSAL)
CLEAN: Taint = frozenset()
FROM_SOURCE: Taint = frozenset((rule, None) for rule in RULES)


def from_param(name: str) -> Taint:
    return frozenset((rule, name) for rule in RULES)


def without(taint: Taint, rule: str) -> Taint:
    """The same taint with one bug class removed (what a sanitizer does)."""
    return frozenset(label for label in taint if label[0] != rule)
