# Responsible disclosure

How findings from this scanner get reported. The scanner flags possible bugs;
this is what happens between a flag and a fix.

## The rule

A finding is private until the maintainer has had a fair chance to fix it.
Never open a public issue, pull request, or post that describes an unfixed
vulnerability, and never name an unconfirmed finding in this repository (the
scan database and `data/` are git-ignored for exactly this reason).

## Steps

1. **Confirm it locally.** A flag is a lead, not a bug. Reproduce it against a
   local copy of the code at the commit the scan pinned, in a sandbox with no
   network (see `poc/` kits). If it cannot be reproduced, drop it.
2. **Find the private channel.** In order of preference: a `SECURITY.md` or
   security policy on the repo, GitHub's private "Report a vulnerability"
   advisory (if the project has it enabled), a security email, then a
   maintainer's listed contact. Do not use the public issue tracker.
3. **Send the report.** Use `TEMPLATE.md`. Keep it short, factual, and helpful:
   what, where, how to reproduce locally, impact, and a suggested fix.
4. **Give time.** 90 days is the common norm before any public write-up, and
   sooner only if the maintainer agrees or ships a fix first. Coordinate the
   disclosure date with them.
5. **Credit and track.** If they want a CVE, GitHub advisories can assign one.
   Keep your own record (date reported, channel, response, fix commit).

## What not to do

- No testing against a live or hosted instance of the project. Local copies
  only.
- No scanning or accessing data that is not yours.
- No demanding a bounty. If one is offered, fine; asking for one alongside a
  report reads as a threat.
- No automated mass mailing of reports. Each one is read and sent by hand.
