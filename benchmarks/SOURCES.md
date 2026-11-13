# Where the benchmark entries come from

Checked on 2026-11-13. Commit hashes were read from the GitHub commit API.

| CVE | Repository | Fix commit | Source |
|---|---|---|---|
| CVE-2024-22203, CVE-2024-22205, CVE-2024-22204 | benbusby/whoogle-search | `3a2e0b26` (parent `8830615a`) | [GitHub Security Lab GHSL-2023-186 to 189](https://securitylab.github.com/advisories/GHSL-2023-186_GHSL-2023-189_benbusby_whoogle-search) |
| CVE-2022-0766 | janeczku/calibre-web | `965352c8` (parent `8007e450`) | [OSV GHSA-2647-c639-qv2j](https://api.osv.dev/v1/vulns/GHSA-2647-c639-qv2j) |
| CVE-2023-52288, CVE-2023-52289 | sujeetkv/flaskcode | none; pinned at `05a9d61c` | [NVD CVE-2023-52289](https://nvd.nist.gov/vuln/detail/CVE-2023-52289) |
| CVE-2022-31506 | cmusatyalab/opendiamond | `398049c1` | [OSV CVE-2022-31506](https://api.osv.dev/v1/vulns/CVE-2022-31506) |
| CVE-2022-31549 | olmax99/helm-flask-celery | `28c985d7` | [OSV CVE-2022-31549](https://api.osv.dev/v1/vulns/CVE-2022-31549) |

## Checked against the code after the first run

- CVE-2024-22204: `app/routes.py` lines 430 and 445 are the two `open()` calls in `config()` that the advisory describes.
- CVE-2022-0766: `cps/helper.py` line 740 is the `requests.get(url)` in `save_cover_from_url`, reached from `cps/editbooks.py`.
- CVE-2023-52288: `flaskcode/views.py` line 22 is the `send_file` in `resource_data`.
- CVE-2023-52289: `flaskcode/utils.py` line 23 is the `io.open` in `write_file`, reached from `update_resource_data`. The benchmark's file-level match credits both flaskcode findings to both CVEs; really it is one each.
- CVE-2022-31549: `app_setup.py` line 83 is the exact line the fix commit's own write-up cites.
- CVE-2022-31506: the fix replaces `os.path.join` with `safe_join` in the flagged files. Only `diamond_store.py` was read; the other seven locations were not checked one by one.

## Not verified

- CVE-2022-0339 (the original Calibre-Web SSRF) is left out because the commit NVD links for it does not look like an SSRF fix.

## Where to get more

CVE-2022-31506 and CVE-2022-31549 are two of roughly 80 CVEs (CVE-2022-31501 to CVE-2022-31588) filed for the same Flask `send_file` pattern, tracked in [github/securitylab issue 669](https://github.com/github/securitylab/issues/669). They are the cheapest way to grow this benchmark.
