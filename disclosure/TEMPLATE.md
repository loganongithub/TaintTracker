# Vulnerability report template

Fill in the placeholders and delete this line and the notes in (parentheses).

---

**Summary:** (one sentence, e.g. "An authenticated user can read arbitrary
files on the server through the `image` field of `/api/chat`.")

**Project:** (name) — **version / commit:** (the exact commit tested)

**Vulnerability class:** (e.g. path traversal / CWE-22, or SSRF / CWE-918)

**Severity:** (your estimate, with a one-line reason. Note what access is
needed: unauthenticated, logged-in user, admin.)

## Where

- Entry point: (file:line — the route that takes the input)
- Sink: (file:line — the dangerous call)
- The untrusted value flows: (source → ... → sink, in a sentence)

## How to reproduce

(Numbered steps against a local copy. Include the exact request. Keep it to
the minimum that demonstrates the problem — a file read, not a full exploit.)

1. ...
2. ...
3. Observe: (what proves it, e.g. "the response contains the contents of
   `/etc/passwd`" or "the server opened a file outside the intended folder")

## Impact

(What an attacker gains. Be accurate and not alarmist. State the preconditions
plainly — if it needs a login or a known password, say so.)

## Suggested fix

(The smallest change that closes it, ideally a line or two. Point at the safe
pattern the project already uses elsewhere if there is one.)

## Disclosure

Reported privately on (date) via (channel). Happy to coordinate a public
disclosure date and to retest a fix. (Do not set an ultimatum; propose ~90
days and adjust with the maintainer.)
